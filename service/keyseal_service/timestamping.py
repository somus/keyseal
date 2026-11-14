"""Timestamps from a list of timestamp authorities, each tried in turn until
one answers with a token for the digest asked for.

All of them failing is an outage (`TimestampUnavailableError`), which the
routes answer 503 so `@keyseal/server` leaves the job for a retry; a token
for another digest when none answered properly is still a refusal.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
from collections.abc import Sequence
from urllib.parse import urlsplit

from asn1crypto import cms
from pyhanko.sign.timestamps import TimeStamper

from .remote_sign import TIMESTAMP_MISMATCH, RemoteSignError

log = logging.getLogger(__name__)

#: How long one authority may take to answer. Two of them failing slowly
#: still leave a timestamp request inside TIMESTAMP_BUDGET_SECONDS.
TSA_TIMEOUT_SECONDS = 10
#: How long one timestamp may take over the whole list: `/finalize` asks
#: for two (one only sizes the document timestamp) within its 45 seconds,
#: and `/sign/finish` answers well inside `@keyseal/server`'s 60.
TIMESTAMP_BUDGET_SECONDS = 20
#: How long an authority that just failed is tried after the others.
COOL_DOWN_SECONDS = 60


class TimestampUnavailableError(Exception):
    pass


def _host(url: str) -> str:
    return urlsplit(url).hostname or url


def _stamps(token: cms.ContentInfo, digest: bytes, md_algorithm: str) -> bool:
    imprint = token["content"]["encap_content_info"]["content"].parsed["message_imprint"]
    return imprint["hash_algorithm"]["algorithm"].native == md_algorithm and hmac.compare_digest(
        imprint["hashed_message"].native, digest
    )


class TimestampAuthorities:
    """The configured authorities, shared by every request, and when each
    last failed, so a dead primary doesn't cost its timeout on every one."""

    def __init__(self, stampers: Sequence[tuple[str, TimeStamper]]) -> None:
        self._stampers = list(stampers)
        self._failed_at: dict[str, float] = {}

    def _order(self) -> list[tuple[str, TimeStamper]]:
        now = time.monotonic()
        # Stable: the configured order, with the ones cooling down last.
        return sorted(
            self._stampers,
            key=lambda entry: (
                now - self._failed_at.get(entry[0], -COOL_DOWN_SECONDS) < COOL_DOWN_SECONDS
            ),
        )

    def stamper(self) -> TimeStamper:
        """A timestamper for one request."""
        return _FallbackTimeStamper(self)

    async def timestamp(
        self,
        message_digest: bytes,
        md_algorithm: str,
        preferred: TimeStamper | None = None,
    ) -> tuple[TimeStamper, cms.ContentInfo]:
        """The first token for `message_digest` and the authority that gave it,
        asking `preferred` first."""
        order = self._order()
        order.sort(key=lambda entry: entry[1] is not preferred)
        deadline = time.monotonic() + TIMESTAMP_BUDGET_SECONDS
        failures: list[str] = []
        mismatched = False
        for url, stamper in order:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                async with asyncio.timeout(min(TSA_TIMEOUT_SECONDS, remaining)):
                    token = await stamper.async_timestamp(message_digest, md_algorithm)
                stamped = _stamps(token, message_digest, md_algorithm)
            except Exception as error:  # noqa: BLE001 - any failure moves on to the next
                failure = type(error).__name__
            else:
                if stamped:
                    self._failed_at.pop(url, None)
                    if failures:
                        log.warning(
                            "Timestamp authority failed: %s; %s answered",
                            ", ".join(failures),
                            _host(url),
                        )
                    return stamper, token
                mismatched = True
                failure = "a token for another digest"
            self._failed_at[url] = time.monotonic()
            failures.append(f"{_host(url)} ({failure})")
        log.error("Every timestamp authority failed: %s", ", ".join(failures) or "out of time")
        if mismatched:
            raise RemoteSignError(TIMESTAMP_MISMATCH)
        raise TimestampUnavailableError("No timestamp authority answered; try again later")


class _FallbackTimeStamper(TimeStamper):
    """Asks the authority that answered last in this request first, so the
    document timestamp comes from the one whose test token sized it and
    whose certificates pyHanko adds validation data for."""

    def __init__(self, authorities: TimestampAuthorities) -> None:
        super().__init__()
        self._authorities = authorities
        self._last: TimeStamper | None = None

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> cms.ContentInfo:
        self._last, token = await self._authorities.timestamp(
            message_digest, md_algorithm, self._last
        )
        return token
