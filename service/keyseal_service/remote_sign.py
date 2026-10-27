"""Signing with a key the service never sees (PAdES, deferred signing).

1. `start`: given the latest PDF, the signer's field and their certificate,
   reserve the signature in the field and return the CMS signed attributes
   the token must sign, plus an opaque state.
2. The signer's helper signs those bytes on their token: RSA PKCS#1 v1.5 or
   RSA-PSS (MGF1, salt as long as the digest) with SHA-256, or ECDSA with
   SHA-256 (P-256) or SHA-384 (P-384) returned as a DER ECDSA-Sig-Value.
3. `finish`: given the state and the signature value, build the CMS with a
   signature timestamp from the TSA (PAdES B-T) and write it into the PDF.

`finalize` makes a fully signed PDF long-term verifiable (PAdES
B-LTA): revocation data for every signature and a document timestamp.
`retimestamp` adds another document timestamp before the last one's
certificate expires.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
from dataclasses import dataclass
from typing import Literal

from asn1crypto import algos, cms, x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.signers.pdf_byterange import PreparedByteRangeDigest
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.sign.validation import async_add_validation_info
from pyhanko_certvalidator import ValidationContext
from pyhanko.stamp import BaseStampStyle
from pyhanko_certvalidator.registry import SimpleCertificateStore

#: Room for the CMS: the signature, the certificate chain and the TSA token.
#: An Indian DSC chain with a TSA token already needs about 13 KB.
BYTES_RESERVED = 65_536
MD = "sha256"

#: What the key that authenticates signing states is derived under.
STATE_KEY_LABEL = b"keyseal-service sign state v1"
#: The sealed state's last member, which only the closing brace follows.
_MAC_MEMBER = ', "mac": "'

RsaPadding = Literal["pkcs1", "pss"]
SignatureAlgorithm = Literal["rsa-pkcs1-v1_5", "rsa-pss", "ecdsa"]

#: Digest, signature mechanism and the largest DER ECDSA-Sig-Value per curve.
_EC = {
    "secp256r1": ("sha256", "sha256_ecdsa", 72),
    "secp384r1": ("sha384", "sha384_ecdsa", 104),
}


class RemoteSignError(ValueError):
    pass


class UnsupportedKeyError(RemoteSignError):
    pass


@dataclass(frozen=True)
class Algorithms:
    digest: str
    mechanism: algos.SignedDigestAlgorithm
    #: The mechanism as the helper names it.
    signature_algorithm: SignatureAlgorithm
    #: Placeholder signature size while the document is prepared.
    signature_size: int


def _pss(digest: str) -> algos.SignedDigestAlgorithm:
    """RSASSA-PSS with MGF1 over the same digest and a salt as long as the digest."""
    digest_algorithm = algos.DigestAlgorithm({"algorithm": digest})
    return algos.SignedDigestAlgorithm(
        {
            "algorithm": "rsassa_pss",
            "parameters": algos.RSASSAPSSParams(
                {
                    "hash_algorithm": digest_algorithm,
                    "mask_gen_algorithm": {"algorithm": "mgf1", "parameters": digest_algorithm},
                    "salt_length": hashlib.new(digest).digest_size,
                }
            ),
        }
    )


def algorithms(cert: x509.Certificate, rsa_padding: RsaPadding = "pkcs1") -> Algorithms:
    """The digest and signature mechanism the certificate's key signs with."""
    key = cert.public_key
    if key.algorithm == "rsa":
        if rsa_padding == "pss":
            return Algorithms(MD, _pss(MD), "rsa-pss", key.byte_size)
        mechanism = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
        return Algorithms(MD, mechanism, "rsa-pkcs1-v1_5", key.byte_size)
    if key.algorithm == "ec":
        kind, curve = key.curve
        if kind == "named" and curve in _EC:
            digest, mechanism, size = _EC[curve]
            return Algorithms(
                digest, algos.SignedDigestAlgorithm({"algorithm": mechanism}), "ecdsa", size
            )
        raise UnsupportedKeyError(
            "Only P-256 and P-384 elliptic-curve DSC certificates are supported"
        )
    raise UnsupportedKeyError("Only RSA and elliptic-curve DSC certificates are supported")


def load_cert(der_b64: str) -> x509.Certificate:
    try:
        # Strict: bytes after the certificate are refused, not ignored, so the
        # certificate checked here is all the caller sent.
        return x509.Certificate.load(base64.b64decode(der_b64, validate=True), strict=True)
    except Exception as error:  # noqa: BLE001
        raise RemoteSignError("Certificate is not DER in base64") from error


def state_key(token: str) -> bytes:
    """The key that authenticates signing states: HMAC-SHA256 of a fixed
    label keyed with the bearer token, so it is never the token itself."""
    return hmac.new(token.encode(), STATE_KEY_LABEL, hashlib.sha256).digest()


def seal_state(key: bytes, state: str) -> str:
    """The state JSON object with a last member `mac`, the HMAC-SHA256 of
    the exact JSON text before it was added."""
    mac = hmac.new(key, state.encode(), hashlib.sha256).hexdigest()
    return f'{state[:-1]}{_MAC_MEMBER}{mac}"}}'


def open_state(key: bytes, sealed: str) -> str:
    """The state `seal_state` sealed, refused unless its MAC matches."""
    body, found, tail = sealed.rpartition(_MAC_MEMBER)
    state = body + "}"
    mac = hmac.new(key, state.encode(), hashlib.sha256).hexdigest()
    if not found or not hmac.compare_digest(tail.encode(), f'{mac}"}}'.encode()):
        raise RemoteSignError("The signing state isn't one this service issued")
    return state


@dataclass(frozen=True)
class SignatureDetails:
    """`/Reason`, `/Location` and `/ContactInfo` of the signature dictionary,
    which viewers show in their signature panel."""

    reason: str | None = None
    location: str | None = None
    contact_info: str | None = None


@dataclass(frozen=True)
class StartResult:
    #: DER of the signed attributes; the token signs exactly these bytes.
    to_sign: bytes
    #: The digest the token hashes `to_sign` with.
    digest_algorithm: str
    #: The mechanism the token signs `to_sign` with.
    signature_algorithm: SignatureAlgorithm
    #: Opaque; hand back unchanged to `finish`.
    state: str


async def start(
    pdf: bytes,
    field_name: str,
    certificate_b64: str,
    chain_b64: list[str],
    stamp_style: BaseStampStyle,
    rsa_padding: RsaPadding = "pkcs1",
    details: SignatureDetails = SignatureDetails(),
) -> StartResult:
    """Reserves the signature in `field_name` and returns what the token signs.

    The details are written into the prepared PDF here, so the sealed state
    carries them to `finish` and `toSign` covers them. The stamp style gets
    them as the text parameters `reason`, `location` and `contact_info`,
    empty when not given.
    """
    cert = load_cert(certificate_b64)
    chosen = algorithms(cert, rsa_padding)
    chain = [load_cert(c) for c in chain_b64]
    try:
        reader = PdfFileReader(io.BytesIO(pdf))
        names = [f[0] for f in fields.enumerate_sig_fields(reader, filled_status=False)]
    except Exception as error:  # noqa: BLE001 - a refusal, not a service failure
        raise RemoteSignError("Not a readable PDF") from error
    if field_name not in names:
        raise RemoteSignError(f"The PDF has no empty field {field_name}")
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    ext = signers.ExternalSigner(
        signing_cert=cert,
        cert_registry=SimpleCertificateStore.from_certs(chain),
        # A placeholder of the right size; the real value comes in `finish`.
        signature_value=bytes(chosen.signature_size),
        signature_mechanism=chosen.mechanism,
    )
    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=chosen.digest,
            subfilter=fields.SigSeedSubFilter.PADES,
            reason=details.reason,
            location=details.location,
            contact_info=details.contact_info,
        ),
        signer=ext,
        stamp_style=stamp_style,
    )
    prep, _tbs, output = await pdf_signer.async_digest_doc_for_signing(
        writer,
        existing_fields_only=True,
        bytes_reserved=BYTES_RESERVED,
        appearance_text_params={
            "reason": details.reason or "",
            "location": details.location or "",
            "contact_info": details.contact_info or "",
        },
    )
    signed_attrs = await ext.signed_attrs(
        prep.document_digest, chosen.digest, use_pades=True
    )
    output.seek(0)
    state = {
        "certificate": certificate_b64,
        "chain": chain_b64,
        "digest": base64.b64encode(prep.document_digest).decode(),
        "digestAlgorithm": chosen.digest,
        "output": base64.b64encode(output.read()).decode(),
        "reservedEnd": prep.reserved_region_end,
        "reservedStart": prep.reserved_region_start,
        "signatureMechanism": base64.b64encode(chosen.mechanism.dump()).decode(),
        "signedAttrs": base64.b64encode(signed_attrs.dump()).decode(),
    }
    return StartResult(
        to_sign=signed_attrs.dump(),
        digest_algorithm=chosen.digest,
        signature_algorithm=chosen.signature_algorithm,
        state=json.dumps(state),
    )


async def finish(
    state_json: str,
    signature_value: bytes,
    timestamper: timestamps.TimeStamper | None,
) -> bytes:
    """Builds the CMS around the token's signature and writes it into the PDF."""
    try:
        state = json.loads(state_json)
        cert = load_cert(state["certificate"])
        chain = [load_cert(c) for c in state["chain"]]
        digest_algorithm = str(state["digestAlgorithm"])
        mechanism = algos.SignedDigestAlgorithm.load(
            base64.b64decode(state["signatureMechanism"])
        )
        signed_attrs = cms.CMSAttributes.load(base64.b64decode(state["signedAttrs"]))
        output = io.BytesIO(base64.b64decode(state["output"]))
        prep = PreparedByteRangeDigest(
            document_digest=base64.b64decode(state["digest"]),
            reserved_region_start=int(state["reservedStart"]),
            reserved_region_end=int(state["reservedEnd"]),
        )
    except (KeyError, ValueError, TypeError) as error:
        raise RemoteSignError("The signing state is damaged") from error
    _verify_signature(cert, mechanism, digest_algorithm, signed_attrs.dump(), signature_value)
    ext = signers.ExternalSigner(
        signing_cert=cert,
        cert_registry=SimpleCertificateStore.from_certs(chain),
        signature_value=signature_value,
        signature_mechanism=mechanism,
    )
    signature_cms = await ext.async_sign_prescribed_attributes(
        digest_algorithm, signed_attrs=signed_attrs, timestamper=timestamper
    )
    await PdfTBSDocument.async_finish_signing(
        output, prepared_digest=prep, signature_cms=signature_cms
    )
    return output.getvalue()


def _verify_signature(
    cert: x509.Certificate,
    mechanism: algos.SignedDigestAlgorithm,
    digest_algorithm: str,
    data: bytes,
    signature: bytes,
) -> None:
    """Refuses a signature that isn't the certificate's over the signed attributes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    public_key = load_der_public_key(cert.public_key.dump())
    digest = hashes.SHA384() if digest_algorithm == "sha384" else hashes.SHA256()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if mechanism.signature_algo == "rsassa_pss":
                rsa_padding = padding.PSS(
                    mgf=padding.MGF1(digest), salt_length=digest.digest_size
                )
            else:
                rsa_padding = padding.PKCS1v15()
            public_key.verify(signature, data, rsa_padding, digest)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            try:
                decode_dss_signature(signature)
            except ValueError as error:
                raise RemoteSignError(
                    "The ECDSA signature must be a DER ECDSA-Sig-Value, not raw r||s"
                ) from error
            public_key.verify(signature, data, ec.ECDSA(digest))
        else:
            raise UnsupportedKeyError("Only RSA and elliptic-curve DSC certificates are supported")
    except InvalidSignature as error:
        raise RemoteSignError(
            "The signature doesn't match the certificate: was the right token used?"
        ) from error


async def finalize(
    pdf: bytes,
    timestamper: timestamps.TimeStamper,
    validation_context: ValidationContext,
) -> bytes:
    """Adds revocation data for every signature and a document timestamp (B-LTA)."""
    buf = io.BytesIO(pdf)
    count = len(PdfFileReader(io.BytesIO(pdf)).embedded_signatures)
    for index in range(count):
        reader = PdfFileReader(buf)
        sig = reader.embedded_signatures[index]
        out = io.BytesIO()
        await async_add_validation_info(sig, validation_context, output=out)
        buf = io.BytesIO(out.getvalue())
    writer = IncrementalPdfFileWriter(buf)
    out = io.BytesIO()
    await signers.PdfTimeStamper(timestamper).async_timestamp_pdf(
        writer,
        md_algorithm=MD,
        validation_context=validation_context,
        output=out,
    )
    return out.getvalue()


async def retimestamp(
    pdf: bytes,
    timestamper: timestamps.TimeStamper,
    validation_context: ValidationContext,
) -> bytes:
    """Adds revocation data for the last timestamp and a new document timestamp."""
    reader = PdfFileReader(io.BytesIO(pdf))
    out = io.BytesIO()
    await signers.PdfTimeStamper(timestamper).async_update_archival_timestamp_chain(
        reader, validation_context, output=out
    )
    return out.getvalue()
