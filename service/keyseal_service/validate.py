"""Signature validation for signed PDFs.

The report carries certificate facts and pyHanko's verdicts only, never the
document's text. Matching signers to people is the caller's business.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import logging
from collections.abc import Collection
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from asn1crypto import algos, keys, pem, x509
from cryptography.exceptions import InvalidSignature
from oscrypto import trust_list
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.form_tools import enumerate_fields_in
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    FormUpdatingRule,
    GenericFieldModificationRule,
    SigFieldCreationRule,
    SigFieldModificationRule,
    StandardDiffPolicy,
    SuspiciousModification,
)
from pyhanko.sign.diff_analysis.constants import ACROFORM_EXEMPT_STRICT_COMPARISON
from pyhanko.sign.fields import FieldMDPSpec
from pyhanko.sign.validation import (
    EmbeddedPdfSignature,
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
)
from pyhanko.sign.validation.status import PdfSignatureStatus, SignatureCoverageLevel
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.authority import AuthorityWithCert
from pyhanko_certvalidator.fetchers.api import FetcherBackend
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.sig_validate import (
    DEFAULT_VALIDATION_CONTEXT,
    DefaultSignatureValidator,
    SignatureValidationContext,
)

log = logging.getLogger(__name__)

CERT_SUFFIXES = {".pem", ".cer", ".crt", ".der"}

#: pyHanko's default policy, except that a non-signature field's existing
#: appearance stream can't be rewritten in place. pyHanko (0.37, 0.38) counts
#: every such stream written before the signed revision as rewritten, so a
#: signature that locks a filled text field would fail once anyone else
#: fills or signs later. A changed appearance must be a new stream instead.
#: The first signature also turns /SigFlags from 1 to 3 (append only), which
#: the review from the copy a signer was given has to allow.
DIFF_POLICY = StandardDiffPolicy(
    global_rules=DEFAULT_DIFF_POLICY.global_rules,
    form_rule=FormUpdatingRule(
        field_rules=[
            SigFieldCreationRule(),
            SigFieldModificationRule(),
            GenericFieldModificationRule(allow_in_place_appearance_stream_changes=False),
        ],
        ignored_acroform_keys=ACROFORM_EXEMPT_STRICT_COMPARISON | {"/SigFlags"},
    ),
)


def load_trust_roots(directory: Path | None) -> list[x509.Certificate]:
    """Every certificate in the directory, PEM or DER; unreadable files are logged and skipped."""
    if directory is None or not directory.is_dir():
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
    #: The app's public-only fetcher (`fetching.public_fetch_session`),
    #: shared by every context. Fetching is refused without it: pyHanko's own
    #: would follow certificate URLs to private addresses.
    fetcher_backend: FetcherBackend | None = None

    def context(
        self, moment: datetime | None = None, known: ValidationContext | None = None
    ) -> ValidationContext:
        if self.allow_fetching and self.fetcher_backend is None:
            raise RuntimeError("Certificate fetching requires the managed public fetch session")
        # The system's roots (the TSA's DigiCert chain, Adobe-trusted CAs)
        # plus the configured ones (the CCA India roots behind every DSC),
        # passed explicitly: pyHanko's fallback to the system's is deprecated.
        # At a past `moment`, revocation data issued since still counts, so a
        # certificate revoked before then is refused and one revoked after
        # isn't. The CRLs and OCSP responses a `known` context holds carry
        # over, so a revocation it found still counts if a fetch fails now.
        return ValidationContext(
            trust_roots=[cert for cert, _, _ in trust_list.get_list()] + self.trust_roots,
            other_certs=self.intermediates,
            signature_validator=SIGNATURE_VALIDATOR,
            allow_fetching=self.allow_fetching,
            fetcher_backend=self.fetcher_backend,
            revocation_mode="soft-fail",
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


async def certificate_trusted(
    cert: x509.Certificate, chain: list[x509.Certificate], settings: ValidationSettings
) -> bool:
    """Whether a certificate chains to a configured root and has the key usage
    validation requires of a PDF signer (the DSC enrolment check), so an
    encryption certificate on the same token isn't enrolled."""
    validator = CertificateValidator(
        cert, intermediate_certs=chain, validation_context=settings.context()
    )
    try:
        path = await validator.async_validate_path()
        PdfSignatureStatus.default_usage_constraints().validate(cert)
    except Exception:  # noqa: BLE001 - any path failure means untrusted
        return False
    return settings.is_configured_root(path)


async def _signer_trusted(
    sig: EmbeddedPdfSignature,
    status: PdfSignatureStatus,
    settings: ValidationSettings,
    now: ValidationContext,
) -> bool:
    """Whether the signer's certificate chains to a configured root, now or
    when the signature's trusted timestamp says it was made.

    pyHanko checks the certificate at the context's moment, which is now; the
    signature timestamp is reported beside it and doesn't move that time. A
    certificate revoked or expired since a timestamp is checked again at the
    timestamp's time, with the revocation data `now` (the first check's
    context) found, so a signature proven older than its revocation stands.
    """
    if status.trusted and settings.is_configured_root(status.validation_path):
        return True
    ts = status.timestamp_validity
    if ts is None or not (ts.intact and ts.valid and ts.trusted):
        return False
    then = await async_validate_pdf_signature(
        sig,
        signer_validation_context=settings.context(moment=ts.timestamp, known=now),
        diff_policy=DIFF_POLICY,
        skip_diff=True,
    )
    return bool(then.trusted) and settings.is_configured_root(then.validation_path)


async def _check_signature(
    sig: EmbeddedPdfSignature, settings: ValidationSettings
) -> tuple[PdfSignatureStatus, bool]:
    context = settings.context()
    status = await async_validate_pdf_signature(
        sig, signer_validation_context=context, diff_policy=DIFF_POLICY
    )
    return status, await _signer_trusted(sig, status, settings, context)


def _locks(sig: EmbeddedPdfSignature) -> list[dict[str, Any]]:
    """The fields a signature locks (FieldMDP): the lock in its signature
    dictionary, which validators enforce, and its field's /Lock. An
    unreadable lock counts as locking everything."""
    specs: list[FieldMDPSpec] = []
    try:
        if sig.fieldmdp is not None:
            specs.append(sig.fieldmdp)
        lock = sig.sig_field.get("/Lock")
        if lock is not None and "/Action" in lock.get_object():
            specs.append(FieldMDPSpec.from_pdf_object(lock.get_object()))
    except Exception:  # noqa: BLE001 - unreadable counts as locking all
        return [{"action": "all", "fields": []}]
    return [
        {"action": str(spec.action.value).lstrip("/").lower(), "fields": list(spec.fields or [])}
        for spec in specs
    ]


def _certifies(reader: PdfFileReader, sig: EmbeddedPdfSignature) -> bool:
    """Whether a signature is a certification (DocMDP) signature, by its
    signature dictionary, its field's /Lock or the document's /Perms, all of
    which limit what later signatures may change."""
    try:
        if sig.docmdp_level is not None:
            return True
        perms = reader.root.get("/Perms")
        if perms is None or "/DocMDP" not in perms.get_object():
            return False
        certified = perms.get_object().get_value_as_reference("/DocMDP")
        return certified == sig.sig_object.container_ref
    except Exception:  # noqa: BLE001 - unreadable counts as certifying
        return True


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _common_name(name: x509.Name) -> str | None:
    native = name.native
    cn = native.get("common_name")
    if isinstance(cn, list):
        return cn[0] if cn else None
    return cn


def _certificate_facts(cert: x509.Certificate) -> dict[str, Any]:
    validity = cert["tbs_certificate"]["validity"]
    return {
        "issuer": cert.issuer.human_friendly,
        "notAfter": _iso(validity["not_after"].native),
        "notBefore": _iso(validity["not_before"].native),
        "serial": format(cert.serial_number, "X"),
        "sha256Fingerprint": hashlib.sha256(cert.dump()).hexdigest(),
        "signerName": _common_name(cert.subject),
        "subject": cert.subject.human_friendly,
    }


def _text_fields(reader: PdfFileReader) -> dict[str, str]:
    """Every text field's value in the latest revision; empty when unset."""
    try:
        fields = reader.root["/AcroForm"]["/Fields"]
    except KeyError:
        return {}
    return {
        name: str(value) if value is not None else ""
        for name, value, _ in enumerate_fields_in(
            fields, refs_seen=set(), target_field_type="/Tx"
        )
    }


#: Deeper field trees than this count as malformed.
MAX_FIELD_DEPTH = 64


def _field_chain(widget: generic.DictionaryObject) -> list[generic.DictionaryObject]:
    """The widget and its ancestors up the field tree. A /Parent that loops,
    or a tree deeper than MAX_FIELD_DEPTH, is malformed and stops the walk,
    so a crafted PDF can't keep the service busy forever."""
    chain: list[generic.DictionaryObject] = []
    seen: set[int] = set()
    node: generic.DictionaryObject | None = widget
    while node is not None and id(node) not in seen:
        if len(chain) == MAX_FIELD_DEPTH:
            raise PdfReadError("Field tree too deep")
        seen.add(id(node))
        chain.append(node)
        node = node["/Parent"] if "/Parent" in node else None
    if node is not None:
        raise PdfReadError("Field tree loops")
    return chain


def _field_name(widget: generic.DictionaryObject) -> str:
    """The fully qualified name of the field a widget belongs to."""
    parts = [str(node["/T"]) for node in _field_chain(widget) if "/T" in node]
    return ".".join(reversed(parts))


#: A field's links to the page and form tree, which the walk doesn't follow.
TREE_KEYS = {"/P", "/Parent", "/Kids"}
#: What signing a prepared signature field changes on it.
SIGNING_KEYS = {"/V", "/AP"}


def _digest_object(
    obj: generic.PdfObject, digest: Any, path: frozenset[tuple[int, int]]
) -> None:
    """Feeds an object's resolved content to the digest, whatever objects hold it."""
    if isinstance(obj, generic.IndirectObject):
        ref = (obj.idnum, obj.generation)
        if ref in path:
            digest.update(b"<cycle>")
        else:
            _digest_object(obj.get_object(), digest, path | {ref})
    elif isinstance(obj, generic.DictionaryObject):
        digest.update(b"<<")
        for key in sorted(obj):
            digest.update(repr(key).encode())
            _digest_object(obj.raw_get(key), digest, path)
        digest.update(b">>")
        if isinstance(obj, generic.StreamObject):
            digest.update(b"stream")
            digest.update(obj.encoded_data)
    elif isinstance(obj, generic.ArrayObject):
        digest.update(b"[")
        for index in range(len(obj)):
            _digest_object(obj.raw_get(index), digest, path)
        digest.update(b"]")
    else:
        digest.update(f"{type(obj).__name__}:{obj!r};".encode())


def _rendering(widget: generic.DictionaryObject, signed: bool) -> str:
    """A digest of everything about a widget and its field that decides how it
    shows: flags, rect, appearance streams and their resources, /MK, /DA, /Ff
    and the rest. A field signed since may change only its value and appearance."""
    digest = hashlib.sha256()
    skipped = TREE_KEYS | (SIGNING_KEYS if signed else set())
    for node in _field_chain(widget):
        for key in sorted(k for k in node if k not in skipped):
            digest.update(repr(key).encode())
            _digest_object(node.raw_get(key), digest, frozenset())
        digest.update(b"|")
    return digest.hexdigest()


def _widgets(
    reader: PdfFileReader, signed: Collection[str] = ()
) -> list[tuple[str, int, tuple[float, ...], str]]:
    """Every form field widget on a page: field name, 0-based page, /Rect
    (normalised) and a digest of how it renders (`signed` fields aside)."""
    found: list[tuple[str, int, tuple[float, ...], str]] = []
    for index in range(int(reader.root["/Pages"]["/Count"])):
        page = reader.find_page_for_modification(index)[0].get_object()
        for ref in page["/Annots"] if "/Annots" in page else ():
            annot = ref.get_object()
            if "/Subtype" not in annot or annot["/Subtype"] != "/Widget":
                continue
            x1, y1, x2, y2 = (float(v) for v in annot["/Rect"])
            rect = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
            name = _field_name(annot)
            found.append((name, index, rect, _rendering(annot, name in signed)))
    return found


def _signature_fields(reader: PdfFileReader, signed_only: bool = False) -> set[str]:
    try:
        fields = reader.root["/AcroForm"]["/Fields"]
    except KeyError:
        return set()
    return {
        name
        for name, value, _ in enumerate_fields_in(
            fields, refs_seen=set(), target_field_type="/Sig"
        )
        if value is not None or not signed_only
    }


def _signed_fields(reader: PdfFileReader) -> set[str]:
    return _signature_fields(reader, signed_only=True)


def _changes_since(reader: PdfFileReader, data: bytes, base_length: int) -> str:
    """The most the revisions appended to the first `base_length` bytes change.

    pyHanko only judges changes made after a signature, so a first signer could
    otherwise rewrite the text in the revision their signature covers. It also
    counts a new signature field's widget, and a new appearance, flags or
    look for an unsigned field's widget, as form filling, so the widgets must
    be the ones the base had, each rendering as it did (a field signed since
    may change only its value and appearance).
    """
    try:
        base = PdfFileReader(io.BytesIO(data[:base_length]), strict=False)
        last = base.xrefs.total_revisions - 1
        # The appended update must build on the base's last revision.
        if reader.xrefs.get_startxref_for_revision(
            last
        ) != base.xrefs.get_startxref_for_revision(last):
            return "OTHER"
        result = DIFF_POLICY.review_file(reader, last)
        signed_since = _signed_fields(reader) - _signed_fields(base)
        before = sorted(_widgets(base, signed_since))
        after = sorted(_widgets(reader, signed_since))
        # Asked to, a viewer redraws every field from its value and /DR.
        redraw_before, redraw_after = (
            str(r.root["/AcroForm"].get("/NeedAppearances", False))
            for r in (base, reader)
        )
    except Exception:  # noqa: BLE001 - unreadable counts as changed
        return "OTHER"
    if (
        isinstance(result, SuspiciousModification)
        or before != after
        or redraw_before != redraw_after
    ):
        return "OTHER"
    return result.modification_level.name


def validate_pdf(
    data: bytes, settings: ValidationSettings, base_length: int | None = None
) -> dict[str, Any]:
    """Synchronous form of `validate_pdf_async`, for scripts and tests."""
    return asyncio.run(validate_pdf_async(data, settings, base_length))


async def validate_pdf_async(
    data: bytes, settings: ValidationSettings, base_length: int | None = None
) -> dict[str, Any]:
    """Validate every signature in a PDF; `status` sums them up. With
    `base_length`, `changesSinceBase` is the most the revisions appended to
    that many leading bytes (the copy a signer was given) change, and
    `baseSignatureFields` names the signature fields that copy had."""
    checked_at = datetime.now(UTC).isoformat()
    try:
        reader = PdfFileReader(io.BytesIO(data), strict=False)
        embedded = list(reader.embedded_signatures)
        text_fields = _text_fields(reader)
    except Exception as error:  # noqa: BLE001 - any parser failure is reported, not raised
        log.warning("Not a readable PDF: %s", type(error).__name__)
        return {
            "checkedAt": checked_at,
            "message": f"Not a readable PDF: {type(error).__name__}",
            "signatures": [],
            "status": "invalid",
            "textFields": {},
        }

    if not embedded:
        return {
            "checkedAt": checked_at,
            "signatures": [],
            "status": "no_signatures",
            "textFields": text_fields,
        }

    signatures: list[dict[str, Any]] = []
    document_timestamps: list[dict[str, Any]] = []
    all_good = True
    for sig in embedded:
        if sig.sig_object_type == "/DocTimeStamp":
            try:
                ts_status = await async_validate_pdf_timestamp(
                    sig, validation_context=settings.context()
                )
                intact = bool(ts_status.intact and ts_status.valid)
                document_timestamps.append(
                    {
                        "intact": intact,
                        "time": _iso(ts_status.timestamp),
                        "trusted": bool(ts_status.trusted),
                    }
                )
                all_good = all_good and intact
            except Exception as error:  # noqa: BLE001
                all_good = False
                document_timestamps.append(
                    {"error": type(error).__name__, "intact": False, "time": None, "trusted": False}
                )
            continue
        try:
            try:
                status, trusted = await _check_signature(sig, settings)
            except TimeoutError:
                # pyHanko's soft-fail covers a responder that refuses the
                # connection but not one that never answers, as Indian CAs'
                # OCSP servers do outside India. Either way the revocation
                # data is unavailable, so check without fetching.
                if not settings.allow_fetching:
                    raise
                log.warning("Revocation fetch timed out for %s; checking without fetching", sig.field_name)
                status, trusted = await _check_signature(
                    sig, replace(settings, allow_fetching=False)
                )
        except Exception as error:  # noqa: BLE001 - report, don't crash
            log.exception("Checking the signature in %s failed", sig.field_name)
            all_good = False
            signatures.append(
                {
                    "certifies": _certifies(reader, sig),
                    "coversWholeRevision": False,
                    "fieldName": sig.field_name,
                    "intact": False,
                    "issuer": "",
                    "locks": _locks(sig),
                    "modificationLevel": None,
                    "notAfter": None,
                    "notBefore": None,
                    "serial": "",
                    "sha256Fingerprint": "",
                    "signerName": None,
                    "signingTime": None,
                    "subject": "",
                    "timestamped": False,
                    "trusted": False,
                    "error": type(error).__name__,
                }
            )
            continue
        covers = status.coverage is not None and (
            status.coverage >= SignatureCoverageLevel.ENTIRE_REVISION
        )
        intact = bool(status.intact and status.valid)
        docmdp_ok = status.docmdp_ok is not False
        if not (intact and covers and docmdp_ok):
            all_good = False
        signatures.append(
            {
                **_certificate_facts(status.signing_cert),
                "certifies": _certifies(reader, sig),
                "coversWholeRevision": covers,
                "fieldName": sig.field_name,
                "intact": intact,
                "locks": _locks(sig),
                "modificationLevel": (
                    status.modification_level.name
                    if status.modification_level is not None
                    else None
                ),
                "signingTime": _iso(status.signer_reported_dt),
                "timestamped": status.timestamp_validity is not None,
                "trusted": trusted,
            }
        )

    report: dict[str, Any] = {
        "checkedAt": checked_at,
        "signatures": signatures,
        "status": (
            "no_signatures" if not signatures else ("valid" if all_good else "invalid")
        ),
        "textFields": text_fields,
    }
    if document_timestamps:
        report["documentTimestamps"] = document_timestamps
    if base_length is not None:
        report["changesSinceBase"] = _changes_since(reader, data, base_length)
        try:
            base = PdfFileReader(io.BytesIO(data[:base_length]), strict=False)
            report["baseSignatureFields"] = sorted(_signature_fields(base))
        except Exception:  # noqa: BLE001 - unreadable counts as changed
            report["changesSinceBase"] = "OTHER"
    return report
