"""CRLs, OCSP responses and issuer certificates a request fetched, kept in
memory for later requests until their own nextUpdate.

Each request validates on its own worker thread and event loop with its own
fetch session (`app._validating`), so the cache is shared across threads and
holds DER bytes, parsed again by each request: a parsed CRL is read lazily
and grows as pyHanko walks it, to about 24 times its DER for a large one,
and only a fraction of the walk is saved by sharing it.

pyHanko's fetchers are subclassed where they fetch one URL (CRLs, issuer
certificates) or one certificate's status (OCSP); a hit goes through the
same per-request bookkeeping as a fetch, so the validation context lists it
among what it fetched and pyHanko's own checks see no difference. OCSP
nonces are checked when a response is fetched; a later request reuses the
response like any other the validation context holds. Validity is still
checked by pyHanko for each validation, at its moment.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Hashable
from datetime import UTC, datetime

import aiohttp
from asn1crypto import crl, ocsp, x509
from pyhanko_certvalidator.authority import Authority
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.cert_fetch_client import (
    AIOHttpCertificateFetcher,
)
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.crl_client import AIOHttpCRLFetcher
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.ocsp_client import AIOHttpOCSPFetcher
from pyhanko_certvalidator.fetchers.api import Fetchers
from pyhanko_certvalidator.fetchers.common_utils import FetchBudget
from pyhanko_certvalidator.util import issuer_serial

#: Room for several of the largest CRLs `fetching.MAX_CRL_BYTES` allows.
MAX_CACHE_BYTES = 64 * 1024 * 1024


class FetchCache:
    """DER by key, each until it expires, least recently used evicted first
    past `max_bytes`. Safe across threads."""

    def __init__(self, max_bytes: int = MAX_CACHE_BYTES) -> None:
        self._max_bytes = max_bytes
        self._entries: OrderedDict[Hashable, tuple[datetime | None, tuple[bytes, ...]]] = (
            OrderedDict()
        )
        self._size = 0
        self._lock = threading.Lock()

    def get(self, key: Hashable) -> tuple[bytes, ...] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires, ders = entry
            if expires is not None and expires <= datetime.now(UTC):
                self._remove(key)
                return None
            self._entries.move_to_end(key)
            return ders

    def put(self, key: Hashable, ders: tuple[bytes, ...], expires: datetime | None) -> None:
        """Keeps `ders` until `expires`, or until evicted when that is None."""
        size = sum(len(der) for der in ders)
        if size > self._max_bytes or (expires is not None and expires <= datetime.now(UTC)):
            return
        with self._lock:
            if key in self._entries:
                self._remove(key)
            self._entries[key] = (expires, ders)
            self._size += size
            while self._size > self._max_bytes:
                self._remove(next(iter(self._entries)))

    def _remove(self, key: Hashable) -> None:
        _, ders = self._entries.pop(key)
        self._size -= sum(len(der) for der in ders)


def _crl_expiry(certificate_list: crl.CertificateList) -> datetime | None:
    return certificate_list["tbs_cert_list"]["next_update"].native


def _ocsp_expiry(response: ocsp.OCSPResponse) -> datetime | None:
    """The earliest nextUpdate of its answers; None when any has none, which
    RFC 6960 means as newer status always being available."""
    answers = response["response_bytes"]["response"].parsed["tbs_response_data"]["responses"]
    updates = [answer["next_update"].native for answer in answers]
    if not updates or None in updates:
        return None
    return min(updates)


class _CachingCRLFetcher(AIOHttpCRLFetcher):
    def __init__(self, cache: FetchCache, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._cache = cache

    async def _single_fetch(self, url: str) -> crl.CertificateList:
        key = ("crl", url)
        cached = self._cache.get(key)
        if cached is not None:

            async def hit() -> crl.CertificateList:
                return crl.CertificateList.load(cached[0])

            return await self._post_fetch_task(url, hit)
        fetched = await super()._single_fetch(url)
        expires = _crl_expiry(fetched)
        if expires is not None:
            self._cache.put(key, (fetched.dump(),), expires)
        return fetched


class _CachingOCSPFetcher(AIOHttpOCSPFetcher):
    def __init__(self, cache: FetchCache, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._cache = cache

    async def _fetch(self, cert: x509.Certificate, authority: Authority) -> ocsp.OCSPResponse:
        key = ("ocsp", issuer_serial(cert), authority.public_key.sha256)
        cached = self._cache.get(key)
        if cached is not None:
            return ocsp.OCSPResponse.load(cached[0])
        fetched = await super()._fetch(cert, authority)
        expires = _ocsp_expiry(fetched)
        if expires is not None:
            self._cache.put(key, (fetched.dump(),), expires)
        return fetched


class _CachingCertificateFetcher(AIOHttpCertificateFetcher):
    def __init__(self, cache: FetchCache, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._cache = cache

    async def fetch_certs(self, url: str, url_origin_type: str) -> list[x509.Certificate]:
        # A certificate doesn't change, so it is kept until evicted.
        key = ("certs", url)
        cached = self._cache.get(key)
        if cached is not None:

            async def hit() -> list[x509.Certificate]:
                return [x509.Certificate.load(der) for der in cached]

            return await self._post_fetch_task(url, hit)
        fetched = await super().fetch_certs(url, url_origin_type)
        self._cache.put(key, tuple(cert.dump() for cert in fetched), None)
        return fetched


class CachingFetcherBackend(AIOHttpFetcherBackend):
    """pyHanko's aiohttp fetchers over `session`, answering from `cache`
    what an earlier request fetched."""

    def __init__(self, cache: FetchCache, session: aiohttp.ClientSession) -> None:
        super().__init__(session=session)
        self._cache = cache

    def get_fetchers(self) -> Fetchers:
        args = (self._cache, self.session)
        options = {
            "per_request_timeout": self.per_request_timeout,
            "budget": FetchBudget(self.limits),
        }
        return Fetchers(
            ocsp_fetcher=_CachingOCSPFetcher(*args, **options),
            crl_fetcher=_CachingCRLFetcher(*args, **options),
            cert_fetcher=_CachingCertificateFetcher(*args, **options),
        )
