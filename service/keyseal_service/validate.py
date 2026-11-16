"""Signature validation for signed PDFs.

The report carries certificate facts and pyHanko's verdicts only, never the
document's text. Matching signers to people is the caller's business.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import Any, TypeVar

from asn1crypto import x509
from pyhanko.pdf_utils.form_tools import enumerate_fields_in
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import FieldMDPSpec
from pyhanko.sign.validation import (
    EmbeddedPdfSignature,
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
)
from pyhanko.sign.validation.status import PdfSignatureStatus, SignatureCoverageLevel
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.path import ValidationPath
from pyhanko_certvalidator.validate import async_validate_path

from .base_review import DIFF_POLICY, changes_since, signature_fields
from .trust import DEFAULT_KEY_USAGE, KeyUsage, ValidationSettings, key_usage_constraints

log = logging.getLogger(__name__)

T = TypeVar("T")


async def _without_fetching_on_timeout(
    check: Callable[[ValidationSettings], Awaitable[T]],
    settings: ValidationSettings,
    subject: str,
) -> T:
    """`check` with `settings`, run again without fetching when a revocation
    fetch times out. pyHanko's soft-fail covers a responder that refuses the
    connection but not one that never answers, as Indian CAs' OCSP servers
    do outside India. Either way the revocation data is unavailable."""
    try:
        return await check(settings)
    except TimeoutError:
        if not settings.allow_fetching:
            raise
        log.warning("Revocation fetch timed out for %s; checking without fetching", subject)
        return await check(replace(settings, allow_fetching=False))


async def _revocation_checked(
    path: ValidationPath,
    settings: ValidationSettings,
    known: ValidationContext,
    moment: datetime | None = None,
) -> bool:
    """Whether every certificate on a trusted path that names a CRL or OCSP
    responder has revocation data that checked out, among what `known` (the
    context that trusted it) holds. The soft-fail check trusts a certificate
    whose data is missing, as it always is with fetching off, so a revoked
    certificate passes it; this re-checks the path in hard-fail mode without
    fetching anything."""
    context = replace(settings, allow_fetching=False).context(
        moment=moment, known=known, revocation_mode="hard-fail"
    )
    try:
        await async_validate_path(context, path)
    except Exception:  # noqa: BLE001 - any failure means not checked
        return False
    return True


async def certificate_trusted(
    cert: x509.Certificate,
    chain: list[x509.Certificate],
    settings: ValidationSettings,
    key_usage: KeyUsage = DEFAULT_KEY_USAGE,
) -> tuple[bool, bool]:
    """Whether a certificate chains to a configured root, isn't a CA's and
    has the key usage `key_usage` asks of a PDF signer (the DSC enrolment
    check), so an encryption certificate on the same token isn't enrolled,
    and whether its revocation status was checked (`_revocation_checked`).

    A check that runs past VALIDATION_BUDGET_SECONDS, fetches included,
    raises `ValidationLimitError`."""
    async with within_budget("The certificate check"):
        return await _certificate_trusted(cert, chain, settings, key_usage)


async def _certificate_trusted(
    cert: x509.Certificate,
    chain: list[x509.Certificate],
    settings: ValidationSettings,
    key_usage: KeyUsage,
) -> tuple[bool, bool]:
    if cert.ca:
        log.info("Certificate refused: a CA certificate")
        return False, False
    # Built outside the try, so settings that can't build one raise rather
    # than count as untrusted.
    context = settings.context()

    async def validated_path(
        checking: ValidationSettings,
    ) -> tuple[ValidationPath, ValidationContext]:
        used = context if checking is settings else checking.context()
        path = await CertificateValidator(
            cert, intermediate_certs=chain, validation_context=used
        ).async_validate_path()
        return path, used

    try:
        path, context = await _without_fetching_on_timeout(
            validated_path, settings, "a certificate"
        )
        key_usage_constraints(key_usage).validate(cert)
    except Exception as error:  # noqa: BLE001 - any path failure means untrusted
        log.info("Certificate refused: %s: %s", type(error).__name__, error)
        return False, False
    if not settings.is_configured_root(path):
        return False, False
    return True, await _revocation_checked(path, settings, context)


async def _signer_trusted(
    sig: EmbeddedPdfSignature,
    status: PdfSignatureStatus,
    settings: ValidationSettings,
    now: ValidationContext,
    key_usage: KeyUsage,
) -> tuple[bool, bool]:
    """Whether the signer's certificate chains to a configured root, now or
    when the signature's trusted timestamp says it was made, and whether its
    revocation status was checked then (`_revocation_checked`).

    pyHanko checks the certificate at the context's moment, which is now; the
    signature timestamp is reported beside it and doesn't move that time. A
    certificate revoked or expired since a timestamp is checked again at the
    timestamp's time, with the revocation data `now` (the first check's
    context) found, so a signature proven older than its revocation stands.
    """
    if status.trusted and settings.is_configured_root(status.validation_path):
        return True, await _revocation_checked(status.validation_path, settings, now)
    ts = status.timestamp_validity
    if ts is None or not (ts.intact and ts.valid and ts.trusted):
        return False, False
    context = settings.context(moment=ts.timestamp, known=now)
    then = await async_validate_pdf_signature(
        sig,
        signer_validation_context=context,
        diff_policy=DIFF_POLICY,
        key_usage_settings=key_usage_constraints(key_usage),
        skip_diff=True,
    )
    if not (then.trusted and settings.is_configured_root(then.validation_path)):
        return False, False
    return True, await _revocation_checked(
        then.validation_path, settings, context, moment=ts.timestamp
    )


async def _check_signature(
    sig: EmbeddedPdfSignature, settings: ValidationSettings, key_usage: KeyUsage
) -> tuple[PdfSignatureStatus, bool, bool]:
    context = settings.context()
    status = await async_validate_pdf_signature(
        sig,
        signer_validation_context=context,
        diff_policy=DIFF_POLICY,
        key_usage_settings=key_usage_constraints(key_usage),
    )
    return status, *await _signer_trusted(sig, status, settings, context, key_usage)


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


@dataclass(frozen=True, kw_only=True)
class SignatureReport:
    """One signature in a validation report, its keys in the order the JSON
    has them. The defaults are what a signature that couldn't be checked
    reports, with `error` naming why; the JSON leaves `error` out without one."""

    issuer: str = ""
    notAfter: str | None = None
    notBefore: str | None = None
    serial: str = ""
    sha256Fingerprint: str = ""
    signerName: str | None = None
    subject: str = ""
    certifies: bool
    coversWholeRevision: bool = False
    fieldName: str
    intact: bool = False
    locks: list[dict[str, Any]]
    modificationLevel: str | None = None
    revocationChecked: bool = False
    signingTime: str | None = None
    timestamped: bool = False
    timestampValid: bool | None = None
    trusted: bool = False
    error: str | None = None

    def as_json(self) -> dict[str, Any]:
        report = asdict(self)
        if self.error is None:
            del report["error"]
        return report


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


#: Signatures and document timestamps one validation checks, or one
#: finalisation adds revocation data for. Each is checked against every
#: revision after it, so the work grows with the square.
MAX_SIGNATURES = 50
#: Wall-clock time one validation, certificate check, finalisation or
#: retimestamping may take, fetches included, under the 60-second request
#: timeout `@keyseal/server` uses by default.
VALIDATION_BUDGET_SECONDS = 45


class ValidationLimitError(ValueError):
    pass


@asynccontextmanager
async def within_budget(work: str) -> AsyncIterator[None]:
    """Stops `work` at its next await once it runs past
    VALIDATION_BUDGET_SECONDS, raising `ValidationLimitError`. A synchronous
    step already running (parsing, diff analysis) finishes first."""
    try:
        async with asyncio.timeout(VALIDATION_BUDGET_SECONDS):
            yield
    except TimeoutError as error:
        raise ValidationLimitError(
            f"{work} took longer than {VALIDATION_BUDGET_SECONDS} seconds"
        ) from error


async def validate_pdf_async(
    data: bytes,
    settings: ValidationSettings,
    base_length: int | None = None,
    key_usage: KeyUsage = DEFAULT_KEY_USAGE,
) -> dict[str, Any]:
    """Validate every signature in a PDF; `status` sums them up. With
    `base_length`, `changesSinceBase` is the most the revisions appended to
    that many leading bytes (the copy a signer was given) change, and
    `baseSignatureFields` names the signature fields that copy had. A
    signer is trusted only with the key usage `key_usage` asks for.

    A PDF with more than MAX_SIGNATURES signatures, or a validation that runs
    past VALIDATION_BUDGET_SECONDS, raises `ValidationLimitError`. The budget
    stops the work at its next await, so a synchronous step already running
    (parsing, pyHanko's diff analysis) finishes first."""
    async with within_budget("Validation"):
        return await _validate_pdf(data, settings, base_length, key_usage)


async def _validate_pdf(
    data: bytes, settings: ValidationSettings, base_length: int | None, key_usage: KeyUsage
) -> dict[str, Any]:
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

    if len(embedded) > MAX_SIGNATURES:
        raise ValidationLimitError(f"More than {MAX_SIGNATURES} signatures")

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
            status, trusted, revocation_checked = await _without_fetching_on_timeout(
                lambda checking: _check_signature(sig, checking, key_usage),
                settings,
                sig.field_name,
            )
        except Exception as error:  # noqa: BLE001 - report, don't crash
            log.exception("Checking the signature in %s failed", sig.field_name)
            all_good = False
            signatures.append(
                SignatureReport(
                    certifies=_certifies(reader, sig),
                    fieldName=sig.field_name,
                    locks=_locks(sig),
                    error=type(error).__name__,
                ).as_json()
            )
            continue
        covers = status.coverage is not None and (
            status.coverage >= SignatureCoverageLevel.ENTIRE_REVISION
        )
        intact = bool(status.intact and status.valid)
        docmdp_ok = status.docmdp_ok is not False
        ts = status.timestamp_validity
        timestamp_valid = None if ts is None else bool(ts.intact and ts.valid)
        if not (intact and covers and docmdp_ok and timestamp_valid is not False):
            all_good = False
        signatures.append(
            SignatureReport(
                **_certificate_facts(status.signing_cert),
                certifies=_certifies(reader, sig),
                coversWholeRevision=covers,
                fieldName=sig.field_name,
                intact=intact,
                locks=_locks(sig),
                modificationLevel=(
                    status.modification_level.name
                    if status.modification_level is not None
                    else None
                ),
                revocationChecked=revocation_checked,
                signingTime=_iso(status.signer_reported_dt),
                timestamped=ts is not None,
                timestampValid=timestamp_valid,
                trusted=trusted,
            ).as_json()
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
        report["changesSinceBase"] = changes_since(reader, data, base_length)
        try:
            base = PdfFileReader(io.BytesIO(data[:base_length]), strict=False)
            report["baseSignatureFields"] = sorted(signature_fields(base))
        except Exception:  # noqa: BLE001 - unreadable counts as changed
            report["changesSinceBase"] = "OTHER"
    return report
