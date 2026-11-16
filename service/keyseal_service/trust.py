"""What the service trusts: the configured roots and intermediates, the
system's roots, the key usage a signer must assert, and the signature check
that also accepts the Income Tax Department's PKCS#1 encoding."""

from __future__ import annotations

import hashlib
import hmac
import logging
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache
from pathlib import Path
from typing import Literal

from asn1crypto import algos, keys, pem, x509
from cryptography.exceptions import InvalidSignature
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.authority import AuthorityWithCert
from pyhanko_certvalidator.fetchers.api import FetcherBackend
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.sig_validate import (
    DEFAULT_VALIDATION_CONTEXT,
    DefaultSignatureValidator,
    SignatureValidationContext,
)

#: The logger these records have always come from, so the log reads as before.
log = logging.getLogger("keyseal_service.validate")

TRUST = Path(__file__).resolve().parent / "trust"
CERT_SUFFIXES = {".pem", ".cer", ".crt", ".der"}

#: The key usage a signer's certificate must assert: nonRepudiation, or with
#: "digitalSignature" either digitalSignature or nonRepudiation. A certificate
#: without a KeyUsage extension asserts neither.
KeyUsage = Literal["nonRepudiation", "digitalSignature"]
DEFAULT_KEY_USAGE: KeyUsage = "nonRepudiation"


class TrustRootsError(ValueError):
    pass


def key_usage_constraints(key_usage: KeyUsage) -> KeyUsageConstraints:
    if key_usage == "digitalSignature":
        return KeyUsageConstraints(key_usage={"digital_signature", "non_repudiation"})
    return KeyUsageConstraints(key_usage={"non_repudiation"})


def load_trust_roots(directory: Path) -> list[x509.Certificate]:
    """Every certificate in the directory, PEM or DER; unreadable files are logged and skipped."""
    if not directory.is_dir():
        return []
    roots: list[x509.Certificate] = []
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in CERT_SUFFIXES:
            continue
        data = path.read_bytes()
        try:
            if pem.detect(data):
                for _, _, der in pem.unarmor(data, multiple=True):
                    roots.append(x509.Certificate.load(der))
            else:
                roots.append(x509.Certificate.load(data))
        except Exception:  # noqa: BLE001 - a bad file must not stop the service
            log.warning("trust root unreadable: %s", path.name)
    return roots


@cache
def system_trust_roots() -> tuple[x509.Certificate, ...]:
    """The platform's trusted roots as OpenSSL finds them by default
    (`SSL_CERT_FILE`, or the image's ca-certificates bundle), read once."""
    context = ssl.create_default_context()
    return tuple(x509.Certificate.load(der) for der in context.get_ca_certs(binary_form=True))


def split_trust_roots(
    certs: list[x509.Certificate],
) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Self-signed certificates are roots; the rest are intermediates."""
    roots = [c for c in certs if c.self_signed != "no"]
    return roots, [c for c in certs if c.self_signed == "no"]


#: DER of the SHA-2 AlgorithmIdentifiers with the parameters left out.
_SHA2_WITHOUT_NULL = {
    "sha256": bytes.fromhex("300b0609608648016503040201"),
    "sha384": bytes.fromhex("300b0609608648016503040202"),
    "sha512": bytes.fromhex("300b0609608648016503040203"),
}


def _pkcs1_without_null(
    signature: bytes,
    signed_data: bytes,
    public_key_info: keys.PublicKeyInfo,
    signature_algorithm: algos.SignedDigestAlgorithm,
    context: SignatureValidationContext,
) -> bool:
    """Whether an RSA PKCS#1 v1.5 signature is valid with the DigestInfo's
    hash parameters left out instead of NULL.

    RFC 8017 (9.2) requires the NULL, but the Income Tax Department's signing
    software omits it and Acrobat accepts that. The recovered block must equal,
    byte for byte, the one encoding that differs from the standard by the
    missing NULL, so nothing in it is parsed and no other variant passes.
    """
    try:
        if signature_algorithm.signature_algo != "rsassa_pkcs1v15" or context.prehashed:
            return False
        try:
            hash_algo = signature_algorithm.hash_algo
        except ValueError:
            hash_algo = context.contextual_md_algorithm
        identifier = _SHA2_WITHOUT_NULL.get(hash_algo or "")
        if identifier is None or public_key_info.algorithm != "rsa":
            return False
        key = public_key_info["public_key"].parsed
        n, e = key["modulus"].native, key["public_exponent"].native
    except (KeyError, ValueError):
        return False
    # OpenSSL's own limits, which refuse such a key before this fallback runs:
    # past them, pow() in Python takes seconds to hours on the event loop.
    if n.bit_length() > 16384 or e.bit_length() > 64:
        return False
    size = (n.bit_length() + 7) // 8
    value = int.from_bytes(signature, "big")
    if len(signature) != size or value >= n:
        return False
    digest = hashlib.new(hash_algo, signed_data).digest()
    body = identifier + bytes([0x04, len(digest)]) + digest
    digest_info = bytes([0x30, len(body)]) + body
    padding = size - 3 - len(digest_info)
    if padding < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    return hmac.compare_digest(pow(value, e, n).to_bytes(size, "big"), expected)


class _SignatureValidator(DefaultSignatureValidator):
    """pyHanko's check, which also accepts the DigestInfo without NULL
    parameters that the Income Tax Department's signatures carry."""

    def validate_signature(
        self,
        signature: bytes,
        signed_data: bytes,
        public_key_info: keys.PublicKeyInfo,
        signature_algorithm: algos.SignedDigestAlgorithm,
        context: SignatureValidationContext = DEFAULT_VALIDATION_CONTEXT,
    ) -> None:
        try:
            super().validate_signature(
                signature, signed_data, public_key_info, signature_algorithm, context
            )
        except InvalidSignature:
            if not _pkcs1_without_null(
                signature, signed_data, public_key_info, signature_algorithm, context
            ):
                raise


SIGNATURE_VALIDATOR = _SignatureValidator()


@dataclass(frozen=True)
class ValidationSettings:
    trust_roots: list[x509.Certificate]
    allow_fetching: bool = False
    #: CA certificates between a signer and a root, for building paths when a
    #: PDF doesn't carry them. Never trust anchors.
    intermediates: list[x509.Certificate] = field(default_factory=list)
    #: A public-only fetcher (`fetching.public_fetch_session`), which the app
    #: opens for each request. Fetching is refused without it: pyHanko's own
    #: would follow certificate URLs to private addresses.
    fetcher_backend: FetcherBackend | None = None

    def context(
        self,
        moment: datetime | None = None,
        known: ValidationContext | None = None,
        revocation_mode: str = "soft-fail",
    ) -> ValidationContext:
        if self.allow_fetching and self.fetcher_backend is None:
            raise RuntimeError("Certificate fetching requires a public fetch session")
        # The system's roots (the TSA's DigiCert chain, Adobe-trusted CAs)
        # plus the configured ones (the CCA India roots behind every DSC),
        # passed explicitly: pyHanko's fallback to the system's is deprecated.
        # At a past `moment`, revocation data issued since still counts, so a
        # certificate revoked before then is refused and one revoked after
        # isn't. The CRLs and OCSP responses a `known` context holds carry
        # over, so a revocation it found still counts if a fetch fails now.
        return ValidationContext(
            trust_roots=[*system_trust_roots(), *self.trust_roots],
            other_certs=self.intermediates,
            signature_validator=SIGNATURE_VALIDATOR,
            allow_fetching=self.allow_fetching,
            fetcher_backend=self.fetcher_backend,
            revocation_mode=revocation_mode,
            moment=moment,
            retroactive_revinfo=moment is not None,
            crls=known.crls if known is not None else None,
            ocsps=known.ocsps if known is not None else None,
        )

    def is_configured_root(self, path: ValidationPath | None) -> bool:
        """Whether a validated path ends in a configured root, not a system one:
        a public CA's certificate in a signer's name is no DSC."""
        if path is None:
            return False
        anchor = path.trust_anchor.authority
        return isinstance(anchor, AuthorityWithCert) and any(
            anchor.certificate.sha256 == root.sha256 for root in self.trust_roots
        )


def trust_settings(
    roots_dir: Path | None, allow_fetching: bool, extra_roots_dir: Path | None = None
) -> ValidationSettings:
    """The bundled CCA India roots and intermediates, or every certificate in
    `roots_dir`, where self-signed ones are roots and the rest intermediates,
    plus every certificate in `extra_roots_dir`, split the same way."""
    if roots_dir is None:
        roots = load_trust_roots(TRUST / "roots")
        intermediates = load_trust_roots(TRUST / "intermediates")
    else:
        roots, intermediates = split_trust_roots(load_trust_roots(roots_dir))
        # A mistyped directory would otherwise start a service that trusts
        # nobody and reports every signature as untrusted.
        if not roots:
            raise TrustRootsError(f"SIGNING_TRUST_ROOTS_DIR {roots_dir} holds no readable root")
    if extra_roots_dir is not None:
        try:
            extra = load_trust_roots(extra_roots_dir)
        except OSError as error:
            raise TrustRootsError(
                f"SIGNING_EXTRA_TRUST_ROOTS_DIR {extra_roots_dir} is unreadable"
            ) from error
        if not extra:
            raise TrustRootsError(
                f"SIGNING_EXTRA_TRUST_ROOTS_DIR {extra_roots_dir} holds no readable certificate"
            )
        extra_roots, extra_intermediates = split_trust_roots(extra)
        roots = roots + extra_roots
        intermediates = intermediates + extra_intermediates
    return ValidationSettings(
        trust_roots=roots, intermediates=intermediates, allow_fetching=allow_fetching
    )
