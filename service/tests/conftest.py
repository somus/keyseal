"""Test fixtures: a throwaway CA, a signer certificate and signed PDFs, the
signing steps the helper takes, stand-in timestamp authorities and an
in-memory network."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import socket
import threading
from collections.abc import Collection
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import aiohttp
import pytest
from asn1crypto import keys, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.timestamps.common_utils import TimestampRequestError
from fastapi.testclient import TestClient
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from keyseal_service import trust
from keyseal_service.app import create_app
from keyseal_service.prepare import FieldRequest, prepare_fields
from keyseal_service.settings import Settings
from keyseal_service.trust import DEFAULT_KEY_USAGE, KeyUsage, ValidationSettings
from keyseal_service.validate import validate_pdf_async

TOKEN = "Test-token-0123456789-abcdefghijkl"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def client_for(
    validation: ValidationSettings, tsa_urls: tuple[str, ...] = (), **options: Any
) -> TestClient:
    return TestClient(
        create_app(Settings(token=TOKEN, tsa_urls=tsa_urls, validation=validation)), **options
    )


def client_with_tsas(
    monkeypatch: pytest.MonkeyPatch,
    validation: ValidationSettings,
    tsas: dict[str, timestamps.TimeStamper],
    **options: Any,
) -> TestClient:
    """A client whose timestamp authorities are `tsas`, by URL, in that order."""
    monkeypatch.setattr(timestamps, "HTTPTimeStamper", lambda url, **_: tsas[url])
    return client_for(validation, tuple(tsas), **options)


def validate_pdf(
    data: bytes,
    settings: ValidationSettings,
    base_length: int | None = None,
    key_usage: KeyUsage = DEFAULT_KEY_USAGE,
) -> dict[str, Any]:
    return asyncio.run(validate_pdf_async(data, settings, base_length, key_usage))


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


#: The arguments of `x509.KeyUsage`, each a flag a certificate may assert.
KEY_USAGE_FLAGS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)


def _cert(
    subject,
    issuer,
    public_key,
    signing_key,
    *,
    ca: bool,
    encryption_only: bool = False,
    time_stamping: bool = False,
    crl_url: str | None = None,
    key_usage: Collection[str] | None | Literal["default"] = "default",
) -> x509.Certificate:
    """A certificate; `key_usage` names the KeyUsage flags it asserts, None
    leaves the extension out."""
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if key_usage == "default":
        if ca:
            key_usage = {"key_cert_sign", "crl_sign"}
        elif encryption_only:
            key_usage = {"key_encipherment"}
        else:
            key_usage = {"digital_signature", "content_commitment"}
    if key_usage is not None:
        builder = builder.add_extension(
            x509.KeyUsage(**{flag: flag in key_usage for flag in KEY_USAGE_FLAGS}), critical=True
        )
    if crl_url:
        # A certificate without one isn't checked for revocation in soft-fail mode.
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl_url)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    if time_stamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
        )
    return builder.sign(signing_key, hashes.SHA256())


def _asn1(cert: x509.Certificate) -> asn1_x509.Certificate:
    return asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))


class Pki:
    def __init__(self) -> None:
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca = _cert(
            _name("Test CCA Root"),
            _name("Test CCA Root"),
            self.ca_key.public_key(),
            self.ca_key,
            ca=True,
        )
        self.signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.signer_cert = _cert(
            _name("PRIYA S RAGHAVAN"),
            _name("Test CCA Root"),
            self.signer_key.public_key(),
            self.ca_key,
            ca=False,
            crl_url="http://crl.invalid/test-root.crl",
        )

    def ec_signer(
        self, curve: ec.EllipticCurve
    ) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        """An elliptic-curve signing key and its certificate under the test root."""
        key = ec.generate_private_key(curve)
        cert = _cert(
            _name("PRIYA S RAGHAVAN"),
            _name("Test CCA Root"),
            key.public_key(),
            self.ca_key,
            ca=False,
            crl_url="http://crl.invalid/test-root.crl",
        )
        return key, cert

    def encryption_cert(self) -> x509.Certificate:
        """The signer's encryption certificate, as a DSC token also carries."""
        return _cert(
            _name("PRIYA S RAGHAVAN"),
            _name("Test CCA Root"),
            self.signer_key.public_key(),
            self.ca_key,
            ca=False,
            encryption_only=True,
        )

    def signing_cert(
        self, key_usage: Collection[str] | None, *, ca: bool = False
    ) -> x509.Certificate:
        """The signer's key under the test root with other key usage flags."""
        return _cert(
            _name("PRIYA S RAGHAVAN"),
            _name("Test CCA Root"),
            self.signer_key.public_key(),
            self.ca_key,
            ca=ca,
            key_usage=key_usage,
        )

    def timestamper(self, at: datetime) -> timestamps.DummyTimeStamper:
        """A TSA under the test root whose timestamps all say `at`."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = _cert(
            _name("Test TSA"),
            _name("Test CCA Root"),
            key.public_key(),
            self.ca_key,
            ca=False,
            time_stamping=True,
        )
        key_der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return timestamps.DummyTimeStamper(
            tsa_cert=_asn1(cert),
            tsa_key=keys.PrivateKeyInfo.load(key_der),
            certs_to_embed=[self.ca_asn1],
            fixed_dt=at,
        )

    def crl(self, signer_revoked_at: datetime | None = None) -> bytes:
        """The root's CRL, issued now, listing the signer's certificate as
        revoked at `signer_revoked_at`, or nothing without it."""
        now = datetime.now(UTC)
        crl = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.ca.subject)
            .last_update(now - timedelta(minutes=1))
            .next_update(now + timedelta(days=1))
        )
        if signer_revoked_at is not None:
            crl = crl.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(self.signer_cert.serial_number)
                .revocation_date(signer_revoked_at)
                .build()
            )
        return crl.sign(self.ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    @property
    def ca_asn1(self) -> asn1_x509.Certificate:
        return _asn1(self.ca)

    def signer(self, cert: x509.Certificate | None = None) -> signers.SimpleSigner:
        key_der = self.signer_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return signers.SimpleSigner(
            signing_cert=_asn1(cert or self.signer_cert),
            signing_key=keys.PrivateKeyInfo.load(key_der),
            cert_registry=SimpleCertificateStore.from_certs([self.ca_asn1]),
        )

    def write_ca(self, directory: Path) -> Path:
        path = directory / "test-root.pem"
        path.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        return path


def misstamping(stamper: timestamps.TimeStamper) -> timestamps.TimeStamper:
    """`stamper`, made to stamp an all-zero digest instead of the one asked for."""
    stamp = stamper.async_timestamp

    async def wrong_digest(message_digest: bytes, md_algorithm: str):  # type: ignore[no-untyped-def]
        return await stamp(bytes(len(message_digest)), md_algorithm)

    stamper.async_timestamp = wrong_digest  # type: ignore[method-assign]
    return stamper


def blank_pdf() -> bytes:
    writer = PdfFileWriter()
    page = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Page"),
            generic.NameObject("/MediaBox"): generic.ArrayObject(
                [generic.NumberObject(n) for n in (0, 0, 595, 842)]
            ),
            generic.NameObject("/Resources"): generic.DictionaryObject(),
        }
    )
    writer.insert_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def certified_no_changes(pdf: bytes, pki: Pki) -> bytes:
    """`pdf` certified (DocMDP) so that no later change is allowed."""
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    out = signers.sign_pdf(
        writer,
        signers.PdfSignatureMetadata(
            field_name="Author", certify=True, docmdp_permissions=fields.MDPPerm.NO_CHANGES
        ),
        signer=pki.signer(),
    )
    return out.getvalue()


def encrypted_pdf() -> bytes:
    """A one-page PDF with an empty signature field `Signer_a`, encrypted
    with an owner password and an empty user password, so it opens without one."""
    writer = PdfFileWriter()
    writer.insert_page(
        generic.DictionaryObject(
            {
                generic.NameObject("/Type"): generic.NameObject("/Page"),
                generic.NameObject("/MediaBox"): generic.ArrayObject(
                    [generic.NumberObject(n) for n in (0, 0, 595, 842)]
                ),
                generic.NameObject("/Resources"): generic.DictionaryObject(),
            }
        )
    )
    fields.append_signature_field(
        writer, fields.SigFieldSpec(sig_field_name="Signer_a", on_page=0, box=(300, 600, 547, 672))
    )
    writer.encrypt("owner-password", "")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def sign(
    pdf: bytes,
    pki: Pki,
    field: str = "Signature1",
    timestamper: timestamps.TimeStamper | None = None,
    cert: x509.Certificate | None = None,
) -> bytes:
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    out = signers.sign_pdf(
        writer,
        signers.PdfSignatureMetadata(field_name=field),
        signer=pki.signer(cert),
        timestamper=timestamper,
    )
    return out.getvalue()


@pytest.fixture(scope="session")
def pki() -> Pki:
    return Pki()


def settings_with(pki: Pki) -> ValidationSettings:
    return ValidationSettings(trust_roots=[pki.ca_asn1])


def with_crl(monkeypatch: pytest.MonkeyPatch, crl: bytes, historical: bool = True) -> None:
    """Every validation context holds `crl`, or with `historical` off only
    those checking at the present."""

    def context(**kwargs: Any) -> ValidationContext:
        if historical or kwargs.get("moment") is None:
            kwargs["crls"] = [*(kwargs.get("crls") or []), crl]
        return ValidationContext(**kwargs)

    monkeypatch.setattr(trust, "ValidationContext", context)


def unanswered(stopped: threading.Event) -> Any:
    """A coroutine function that waits for an answer that never comes,
    setting `stopped` once it is cancelled."""

    async def wait(*_: Any, **__: Any) -> Any:
        try:
            await asyncio.sleep(60)
        finally:
            stopped.set()

    return wait


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def prepared() -> bytes:
    return prepare_fields(
        blank_pdf(),
        [
            FieldRequest(name="Signer_a", page=-1, box=(300, 600, 547, 672)),
            FieldRequest(name="Signer_b", page=-1, box=(300, 470, 547, 542)),
        ],
    )


def token_sign(pki: Pki, data: bytes) -> bytes:
    """What the helper does on the token: RSA PKCS#1 v1.5 over SHA-256."""
    return pki.signer_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def cert_b64(pki: Pki) -> str:
    return b64(pki.signer_cert.public_bytes(serialization.Encoding.DER))


def ca_b64(pki: Pki) -> str:
    return b64(pki.ca.public_bytes(serialization.Encoding.DER))


def _start_with(client: TestClient, pki: Pki, **details: str) -> Any:
    return client.post(
        "/sign/start",
        headers=AUTH,
        json={
            "certificate": cert_b64(pki),
            "chain": [ca_b64(pki)],
            "fieldName": "Signer_a",
            "pdf": b64(prepared()),
            **details,
        },
    )


DIGEST = hashlib.sha256(b"document").digest()


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
