"""The timestamp authority list: fallback, cool-down and outage statuses."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

import pytest
from pyhanko.sign import timestamps
from pyhanko.sign.timestamps.common_utils import TimestampRequestError

from keyseal_service import app as app_module, timestamping
from keyseal_service.remote_sign import TIMESTAMP_MISMATCH, RemoteSignError
from keyseal_service.timestamping import TimestampAuthorities, TimestampUnavailableError
from keyseal_service.validate import ValidationSettings, validate_pdf

from .conftest import AUTH, Pki, blank_pdf, client_for, misstamping, sign
from .test_remote_sign import _start_with, b64, token_sign

DIGEST = hashlib.sha256(b"document").digest()
#: Nothing listens on the discard port, so a real request is refused at once.
REFUSED = "http://127.0.0.1:9"


class Down(timestamps.TimeStamper):
    """A TSA that answers with an error, counting the requests."""

    def __init__(self, error: Exception | None = None) -> None:
        super().__init__()
        self.error = error or TimestampRequestError("Timestamp server refused our request")
        self.requests = 0

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> Any:
        self.requests += 1
        raise self.error


class Silent(timestamps.TimeStamper):
    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> Any:
        await asyncio.sleep(60)


def _stamp(authorities: TimestampAuthorities) -> Any:
    return asyncio.run(authorities.stamper().async_timestamp(DIGEST, "sha256"))


def _imprint(token: Any) -> bytes:
    return (
        token["content"]["encap_content_info"]["content"]
        .parsed["message_imprint"]["hashed_message"]
        .native
    )


def test_the_next_authority_answers_when_one_fails(
    pki: Pki, caplog: pytest.LogCaptureFixture
) -> None:
    down = Down()
    authorities = TimestampAuthorities(
        [
            ("http://down.example/tsa", down),
            ("https://up.example", pki.timestamper(datetime.now(UTC))),
        ]
    )
    with caplog.at_level(logging.WARNING):
        token = _stamp(authorities)
    assert _imprint(token) == DIGEST
    assert down.requests == 1
    assert (
        "Timestamp authority failed: down.example (TimestampRequestError); up.example answered"
        in caplog.text
    )


def test_a_failed_authority_is_tried_last_until_its_cool_down_ends(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(timestamping.time, "monotonic", lambda: clock[0])
    down = Down()
    authorities = TimestampAuthorities(
        [("http://down.example", down), ("http://up.example", pki.timestamper(datetime.now(UTC)))]
    )
    _stamp(authorities)
    _stamp(authorities)
    assert down.requests == 1
    clock[0] += timestamping.COOL_DOWN_SECONDS
    _stamp(authorities)
    assert down.requests == 2


@pytest.mark.parametrize(
    "first",
    [
        Down(TimestampRequestError("Error in communication with timestamp server")),
        Down(OSError("Connection refused")),
        Down(ValueError("Not a TimeStampResp")),
        Silent(),
        timestamps.HTTPTimeStamper(REFUSED),
    ],
    ids=["tsa-error", "connection", "malformed", "timeout", "refused"],
)
def test_any_failure_moves_on(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, first: timestamps.TimeStamper
) -> None:
    monkeypatch.setattr(timestamping, "TSA_TIMEOUT_SECONDS", 0.05)
    authorities = TimestampAuthorities(
        [
            ("http://first.example", first),
            ("http://next.example", pki.timestamper(datetime.now(UTC))),
        ]
    )
    assert _imprint(_stamp(authorities)) == DIGEST


def test_a_token_for_another_digest_moves_on(pki: Pki) -> None:
    authorities = TimestampAuthorities(
        [
            ("http://wrong.example", misstamping(pki.timestamper(datetime.now(UTC)))),
            ("http://right.example", pki.timestamper(datetime.now(UTC))),
        ]
    )
    assert _imprint(_stamp(authorities)) == DIGEST


def test_every_authority_failing_is_an_outage(caplog: pytest.LogCaptureFixture) -> None:
    authorities = TimestampAuthorities(
        [("http://one.example", Down()), ("http://two.example", Down(OSError()))]
    )
    with caplog.at_level(logging.ERROR), pytest.raises(TimestampUnavailableError):
        _stamp(authorities)
    assert (
        "Every timestamp authority failed: one.example (TimestampRequestError),"
        " two.example (OSError)" in caplog.text
    )


def test_only_tokens_for_another_digest_are_refused(pki: Pki) -> None:
    authorities = TimestampAuthorities(
        [
            ("http://down.example", Down()),
            ("http://wrong.example", misstamping(pki.timestamper(datetime.now(UTC)))),
        ]
    )
    with pytest.raises(RemoteSignError, match=TIMESTAMP_MISMATCH):
        _stamp(authorities)


def test_the_list_stops_at_its_budget(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(timestamping, "TSA_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(timestamping, "TIMESTAMP_BUDGET_SECONDS", 0.08)
    authorities = TimestampAuthorities(
        [
            ("http://slow.example", Silent()),
            ("http://slower.example", Silent()),
            ("http://never.example", pki.timestamper(datetime.now(UTC))),
        ]
    )
    with pytest.raises(TimestampUnavailableError):
        _stamp(authorities)


def _with_tsas(pki: Pki, monkeypatch: pytest.MonkeyPatch, *urls: str) -> Any:
    """A client whose TSA list is `urls`: REFUSED is a real request that is
    refused, any other a local TSA under the test root."""
    real = timestamps.HTTPTimeStamper
    monkeypatch.setattr(
        app_module.timestamps,
        "HTTPTimeStamper",
        lambda url, **kw: (
            real(url, **kw) if url.startswith(REFUSED) else pki.timestamper(datetime.now(UTC))
        ),
    )
    return client_for(ValidationSettings(trust_roots=[pki.ca_asn1]), urls)


def _finish(client: Any, pki: Pki) -> Any:
    body = _start_with(client, pki).json()
    return client.post(
        "/sign/finish",
        headers=AUTH,
        json={
            "signature": b64(token_sign(pki, base64.b64decode(body["toSign"]))),
            "state": body["state"],
        },
    )


def test_sign_finish_falls_back_to_the_next_authority(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _with_tsas(pki, monkeypatch, REFUSED, "https://tsa.invalid")
    finished = _finish(client, pki)
    assert finished.status_code == 200
    [sig] = validate_pdf(finished.content, ValidationSettings(trust_roots=[pki.ca_asn1]))[
        "signatures"
    ]
    assert sig["timestampValid"] is True


def test_a_timestamp_outage_is_a_503_so_the_job_survives(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _with_tsas(pki, monkeypatch, REFUSED, REFUSED + "/again")
    finished = _finish(client, pki)
    assert finished.status_code == 503
    assert finished.json() == {"detail": "No timestamp authority answered; try again later"}
    for path in ("/finalize", "/retimestamp"):
        response = client.post(path, headers=AUTH, content=sign(blank_pdf(), pki))
        assert response.status_code == 503
