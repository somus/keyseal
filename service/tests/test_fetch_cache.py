"""Revocation data and issuer certificates fetched once, reused by later
requests until their nextUpdate. The wire is in memory, as in test_fetching."""

from __future__ import annotations

import asyncio
import base64
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID
from fastapi.testclient import TestClient

from keyseal_service import fetch_cache
from keyseal_service.app import create_app
from keyseal_service.fetch_cache import CachingFetcherBackend, FetchCache
from keyseal_service.fetching import public_fetch_session
from keyseal_service.settings import Settings
from keyseal_service.validate import ValidationSettings, certificate_trusted

from .conftest import AUTH, TOKEN, Pki, _asn1, _name, blank_pdf, sign
from .test_fetching import network  # noqa: F401 - the in-memory wire

CRL_URL = "http://crl.invalid/test-root.crl"
OCSP_URL = "http://ocsp.example/"
ISSUER_URL = "http://ca.example/issuer"


def _client(pki: Pki) -> TestClient:
    validation = ValidationSettings(trust_roots=[pki.ca_asn1], allow_fetching=True)
    return TestClient(create_app(Settings(token=TOKEN, tsa_urls=(), validation=validation)))


def _check(client: TestClient, cert: x509.Certificate) -> dict[str, Any]:
    der = cert.public_bytes(serialization.Encoding.DER)
    response = client.post(
        "/certificate", headers=AUTH, json={"certificate": base64.b64encode(der).decode()}
    )
    assert response.status_code == 200
    return response.json()


class _Later(datetime):
    """The cache's clock two days on, past the test CRL's nextUpdate and the
    cache's own oldest age."""

    @classmethod
    def now(cls, tz: Any = None) -> Any:
        return datetime.now(tz) + timedelta(days=2)


def test_a_crl_is_fetched_once_within_its_validity(
    pki: Pki, network: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    network["responses"][CRL_URL] = (200, {}, pki.crl())
    with _client(pki) as client:
        for _ in range(2):
            assert _check(client, pki.signer_cert) == {"revocationChecked": True, "trusted": True}
        assert network["requests"] == [CRL_URL]
        # Past its nextUpdate it is fetched again.
        monkeypatch.setattr(fetch_cache, "datetime", _Later)
        _check(client, pki.signer_cert)
    assert network["requests"] == [CRL_URL, CRL_URL]


def test_a_revoked_certificate_is_refused_from_the_cache(pki: Pki, network: dict[str, Any]) -> None:
    network["responses"][CRL_URL] = (200, {}, pki.crl(datetime.now(UTC) - timedelta(hours=1)))
    with _client(pki) as client:
        for _ in range(2):
            assert _check(client, pki.signer_cert) == {"revocationChecked": False, "trusted": False}
    assert network["requests"] == [CRL_URL]


@pytest.mark.parametrize(
    ("revoked_hours_ago", "trusted"), [(1, True), (3, False)], ids=["after", "before"]
)
def test_a_signature_is_checked_at_its_timestamp_from_cached_data(
    pki: Pki, network: dict[str, Any], revoked_hours_ago: int, trusted: bool
) -> None:
    now = datetime.now(UTC)
    network["responses"][CRL_URL] = (200, {}, pki.crl(now - timedelta(hours=revoked_hours_ago)))
    stamped = sign(blank_pdf(), pki, timestamper=pki.timestamper(now - timedelta(hours=2)))
    with _client(pki) as client:
        for _ in range(2):
            [signature] = client.post("/validate", headers=AUTH, content=stamped).json()[
                "signatures"
            ]
            assert signature["trusted"] is trusted
            assert signature["revocationChecked"] is trusted
    assert network["requests"] == [CRL_URL]


def _with_ocsp(pki: Pki) -> x509.Certificate:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(_name("OCSP Signer"))
        .issuer_name(pki.ca.subject)
        .public_key(pki.signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.KeyUsage(True, True, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL)
                    )
                ]
            ),
            critical=False,
        )
        .sign(pki.ca_key, hashes.SHA256())
    )


def _ocsp_response(pki: Pki, cert: x509.Certificate, next_update: datetime | None) -> bytes:
    now = datetime.now(UTC)
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=pki.ca,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=now - timedelta(minutes=1),
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, pki.ca)
        .sign(pki.ca_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


@pytest.mark.parametrize(("next_update", "fetches"), [(True, 1), (False, 2)])
def test_an_ocsp_response_is_kept_only_with_a_next_update(
    pki: Pki, network: dict[str, Any], next_update: bool, fetches: int
) -> None:
    cert = _with_ocsp(pki)
    until = datetime.now(UTC) + timedelta(hours=1) if next_update else None
    network["responses"][OCSP_URL] = (200, {}, _ocsp_response(pki, cert, until))
    with _client(pki) as client:
        for _ in range(2):
            assert _check(client, cert) == {"revocationChecked": True, "trusted": True}
    assert network["requests"] == [OCSP_URL] * fetches


def test_an_issuer_certificate_is_fetched_once(pki: Pki, network: dict[str, Any]) -> None:
    network["responses"][ISSUER_URL] = (200, {}, pki.ca_asn1.dump())

    async def fetch(backend: CachingFetcherBackend) -> list[bytes]:
        certs = await backend.get_fetchers().cert_fetcher.fetch_certs(ISSUER_URL, "certificate")
        return [cert.dump() for cert in certs]

    async def run(cache: FetchCache) -> list[bytes]:
        async with public_fetch_session() as session:
            return await fetch(CachingFetcherBackend(cache, session))

    cache = FetchCache()
    assert asyncio.run(run(cache)) == asyncio.run(run(cache)) == [pki.ca_asn1.dump()]
    assert network["requests"] == [ISSUER_URL]


def test_the_least_recently_used_entry_is_evicted_past_the_cap() -> None:
    later = datetime.now(UTC) + timedelta(days=1)
    cache = FetchCache(max_bytes=10)
    cache.put("a", (b"aaaa",), later)
    cache.put("b", (b"bbbb",), later)
    assert cache.get("a") == (b"aaaa",)
    cache.put("c", (b"cc", b"cc"), None)
    assert cache.get("b") is None
    assert cache.get("a") == (b"aaaa",)
    assert cache.get("c") == (b"cc", b"cc")
    cache.put("big", (b"x" * 11,), later)
    assert cache.get("big") is None
    assert cache.get("a") == (b"aaaa",)


def test_nothing_is_reused_past_the_oldest_age(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = FetchCache(max_age=timedelta(days=1))
    cache.put("crl", (b"x",), datetime.now(UTC) + timedelta(days=7))
    cache.put("certs", (b"y",), None)
    assert cache.get("crl") == (b"x",)
    assert cache.get("certs") == (b"y",)
    # Two days on: inside the first one's nextUpdate, past the oldest age.
    monkeypatch.setattr(fetch_cache, "datetime", _Later)
    assert cache.get("crl") is None
    assert cache.get("certs") is None


def test_stale_data_is_not_kept() -> None:
    cache = FetchCache()
    cache.put("stale", (b"x",), datetime.now(UTC) - timedelta(seconds=1))
    assert cache.get("stale") is None


def test_two_threads_share_the_cache(pki: Pki, network: dict[str, Any]) -> None:
    network["responses"][CRL_URL] = (200, {}, pki.crl())
    cache = FetchCache()
    settings = ValidationSettings(trust_roots=[pki.ca_asn1], allow_fetching=True)
    signer = _asn1(pki.signer_cert)
    start = threading.Barrier(2)
    results: list[tuple[bool, bool]] = []

    async def check() -> tuple[bool, bool]:
        async with public_fetch_session() as session:
            backend = CachingFetcherBackend(cache, session)
            return await certificate_trusted(signer, [], replace(settings, fetcher_backend=backend))

    def work() -> None:
        start.wait()
        results.append(asyncio.run(check()))

    threads = [threading.Thread(target=work) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [(True, True), (True, True)]
    # Both may have fetched at once; a third finds it kept.
    fetched = len(network["requests"])
    assert 1 <= fetched <= 2
    assert asyncio.run(check()) == (True, True)
    assert len(network["requests"]) == fetched


def test_the_cache_stays_within_its_cap_under_concurrent_use() -> None:
    cache = FetchCache(max_bytes=1000)
    later = datetime.now(UTC) + timedelta(days=1)

    def work(thread: int) -> None:
        for i in range(2000):
            key = (thread, i % 50)
            if cache.get(key) is None:
                cache.put(key, (bytes(37),), later)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert cache._size == sum(len(d) for _, ders in cache._entries.values() for d in ders)
    assert cache._size <= 1000
