"""Test fixtures: a throwaway CA, a signer certificate and signed PDFs."""

from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from asn1crypto import keys, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import signers, timestamps
from fastapi.testclient import TestClient
from pyhanko_certvalidator.registry import SimpleCertificateStore

from keyseal_service.app import create_app
from keyseal_service.settings import Settings
from keyseal_service.validate import ValidationSettings

TOKEN = "Test-token-0123456789-abcdefghijkl"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def client_for(validation: ValidationSettings, tsa_url: str | None = None) -> TestClient:
    return TestClient(create_app(Settings(token=TOKEN, tsa_url=tsa_url, validation=validation)))


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
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
) -> x509.Certificate:
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
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=not encryption_only,
                content_commitment=not encryption_only,
                key_encipherment=encryption_only,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
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

    def signer(self) -> signers.SimpleSigner:
        key_der = self.signer_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return signers.SimpleSigner(
            signing_cert=_asn1(self.signer_cert),
            signing_key=keys.PrivateKeyInfo.load(key_der),
            cert_registry=SimpleCertificateStore.from_certs([self.ca_asn1]),
        )

    def write_ca(self, directory: Path) -> Path:
        path = directory / "test-root.pem"
        path.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        return path


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


def sign(
    pdf: bytes,
    pki: Pki,
    field: str = "Signature1",
    timestamper: timestamps.TimeStamper | None = None,
) -> bytes:
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    out = signers.sign_pdf(
        writer,
        signers.PdfSignatureMetadata(field_name=field),
        signer=pki.signer(),
        timestamper=timestamper,
    )
    return out.getvalue()


@pytest.fixture(scope="session")
def pki() -> Pki:
    return Pki()
