"""Certificate fetching reaches public addresses only. DNS and the wire are
in memory; no test touches the network."""

from __future__ import annotations

import asyncio
import base64
import socket
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import AuthorityInformationAccessOID
from fastapi.testclient import TestClient
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend

from keyseal_service.app import create_app
from keyseal_service.fetching import public_fetch_session, public_socket
from keyseal_service.settings import Settings
from keyseal_service.validate import ValidationSettings

from .conftest import AUTH, TOKEN, Pki, _name

PUBLIC_IP = "93.184.216.34"


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """aiohttp's URL, redirect and DNS handling against an in-memory transport."""
    state: dict[str, Any] = {
        "requests": [],
        "resolved": [],
        "connected": [],
        "answers": [PUBLIC_IP],
        "responses": {},
    }

    async def resolve(self: Any, host: str, port: int = 0, family: int = socket.AF_INET) -> Any:
        state["resolved"].append(host)
        return [
            {
                "hostname": host,
                "host": ip,
                "port": port,
                "family": socket.AF_INET6 if ":" in ip else socket.AF_INET,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            }
            for ip in state["answers"]
        ]

    async def connect(self: Any, *_: Any, addr_infos: Any, req: Any, **__: Any) -> Any:
        # Runs the connector's socket check too, but never connects that socket.
        if self._socket_factory:
            self._socket_factory(addr_infos[0]).close()
        state["connected"].append(addr_infos[0][4][0])
        protocol = self._factory()
        status, headers, body = state["responses"].get(str(req.url), (200, {}, b"synthetic"))
        head = f"HTTP/1.1 {status} Test\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        head += "".join(f"{key}: {value}\r\n" for key, value in headers.items())
        response = (head + "\r\n").encode() + body

        class Transport(asyncio.Transport):
            closed = False
            sent = False

            def is_closing(self) -> bool:
                return self.closed

            def close(self) -> None:
                self.closed = True

            def write(self, data: Any) -> None:
                if not self.sent:
                    self.sent = True
                    state["requests"].append(str(req.url))
                    asyncio.get_running_loop().call_soon(protocol.data_received, response)

            def get_extra_info(self, name: str, default: Any = None) -> Any:
                return default

        transport = Transport()
        protocol.connection_made(transport)
        return transport, protocol

    monkeypatch.setattr(aiohttp.resolver.DefaultResolver, "resolve", resolve)
    monkeypatch.setattr(aiohttp.TCPConnector, "_wrap_create_connection", connect)
    return state


def certificate_with_issuer_url(pki: Pki, url: str) -> str:
    """A signer certificate whose issuer, by its AIA extension, is at `url`."""
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("Synthetic Signer"))
        .issuer_name(pki.ca.subject)
        .public_key(pki.signer_key.public_key())
        .serial_number(42)
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
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(url),
                    )
                ]
            ),
            critical=False,
        )
        .sign(pki.ca_key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def check_certificate(pki: Pki, url: str, allow_fetching: bool = True) -> dict[str, Any]:
    """POST /certificate inside the app's lifespan, which owns the fetch session."""
    validation = ValidationSettings(trust_roots=[], allow_fetching=allow_fetching)
    app = create_app(Settings(token=TOKEN, tsa_url=None, validation=validation))
    with TestClient(app) as client:
        response = client.post(
            "/certificate",
            headers=AUTH,
            json={"certificate": certificate_with_issuer_url(pki, url)},
        )
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize("allow_fetching", [False, True])
def test_an_issuer_url_cannot_reach_loopback(
    pki: Pki, network: dict[str, Any], allow_fetching: bool
) -> None:
    result = check_certificate(pki, "http://127.0.0.1/issuer", allow_fetching)
    assert result == {"revocationChecked": False, "trusted": False}
    assert network["requests"] == network["connected"] == []


def test_with_fetching_off_a_public_issuer_is_not_resolved(
    pki: Pki, network: dict[str, Any]
) -> None:
    check_certificate(pki, "https://ca.example/issuer", allow_fetching=False)
    assert network["resolved"] == network["requests"] == []


@pytest.mark.parametrize(
    "destination",
    [
        "http://127.0.0.1/internal",
        "http://[::1]/internal",
        "http://[::ffff:127.0.0.1]/internal",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/internal",
        "http://172.16.0.1/internal",
        "http://[fe80::1]/internal",
        "http://[fc00::1]/internal",
        "http://224.0.0.1/internal",
        "http://240.0.0.1/internal",
        "file:///etc/hosts",
    ],
)
def test_a_public_redirect_cannot_reach_an_internal_address(
    pki: Pki, network: dict[str, Any], destination: str
) -> None:
    url = "https://ca.example/issuer"
    network["responses"][url] = (302, {"Location": destination}, b"")
    assert check_certificate(pki, url) == {"revocationChecked": False, "trusted": False}
    assert network["requests"] == [url]
    assert network["connected"] == [PUBLIC_IP]


@pytest.mark.parametrize(
    "answers", [["127.0.0.1"], [PUBLIC_IP, "10.0.0.1"], ["::ffff:169.254.169.254"]]
)
def test_every_dns_answer_must_be_public(
    pki: Pki, network: dict[str, Any], answers: list[str]
) -> None:
    network["answers"] = answers
    check_certificate(pki, "https://ca.example/issuer")
    assert network["resolved"] == ["ca.example"]
    assert network["requests"] == network["connected"] == []


def test_a_public_issuer_and_its_redirect_are_fetched(pki: Pki, network: dict[str, Any]) -> None:
    url = "http://ca.example/issuer"
    target = "https://ca.example/root"
    network["responses"][url] = (302, {"Location": target}, b"")
    network["responses"][target] = (
        200,
        {"Content-Type": "application/pkix-cert"},
        pki.ca_asn1.dump(),
    )

    async def run() -> None:
        async with public_fetch_session() as session:
            fetchers = AIOHttpFetcherBackend(session=session).get_fetchers()
            certs = await fetchers.cert_fetcher.fetch_certs(url, "certificate")
            assert [cert.dump() for cert in certs] == [pki.ca_asn1.dump()]
        assert session.closed

    asyncio.run(run())
    assert network["requests"] == [url, target]
    assert network["connected"] == [PUBLIC_IP, PUBLIC_IP]


def test_a_name_rebound_to_loopback_is_refused_on_the_next_connection(
    network: dict[str, Any],
) -> None:
    async def run() -> None:
        async with public_fetch_session() as session:
            async with session.get("http://ca.example/first") as response:
                await response.read()
            network["answers"] = ["127.0.0.1"]
            with pytest.raises(aiohttp.ClientError):
                await session.get("http://ca.example/second")

    asyncio.run(run())
    assert network["resolved"] == ["ca.example", "ca.example"]
    assert network["requests"] == ["http://ca.example/first"]


@pytest.mark.parametrize("proxy", ["http://127.0.0.1:3128", "http://proxy.example:3128"])
def test_a_proxy_is_refused(network: dict[str, Any], proxy: str) -> None:
    async def run() -> None:
        async with public_fetch_session() as session:
            with pytest.raises(aiohttp.ClientConnectionError, match="direct HTTP"):
                await session.get("http://ca.example/issuer", proxy=proxy)

    asyncio.run(run())
    assert network["resolved"] == network["requests"] == []


def test_proxy_environment_variables_are_ignored(
    network: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")

    async def run() -> None:
        async with public_fetch_session() as session:
            async with session.get("http://ca.example/issuer") as response:
                await response.read()

    asyncio.run(run())
    assert network["resolved"] == ["ca.example"]
    assert network["requests"] == ["http://ca.example/issuer"]


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "169.254.169.254",
        "fe80::1",
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "224.0.0.1",
        "ff02::1",
        "240.0.0.1",
    ],
)
def test_the_socket_refuses_a_non_public_address(address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with pytest.raises(OSError):
        public_socket((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 80)))
