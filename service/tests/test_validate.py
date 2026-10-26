from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend

from keyseal_service import validate
from keyseal_service.app import MAX_BODY_BYTES
from keyseal_service.fetching import public_fetch_session
from keyseal_service.validate import ValidationSettings, load_trust_roots, validate_pdf

from .conftest import AUTH, TOKEN, Pki, blank_pdf, client_for, sign
from .test_remote_sign import b64


def settings_with(pki: Pki) -> ValidationSettings:
    return ValidationSettings(trust_roots=[pki.ca_asn1])


def with_crl(monkeypatch: pytest.MonkeyPatch, crl: bytes, historical: bool = True) -> None:
    """Every validation context holds `crl`, or with `historical` off only
    those checking at the present."""

    def context(**kwargs: Any) -> ValidationContext:
        if historical or kwargs.get("moment") is None:
            kwargs["crls"] = [*(kwargs.get("crls") or []), crl]
        return ValidationContext(**kwargs)

    monkeypatch.setattr(validate, "ValidationContext", context)


def test_unsigned_pdf_has_no_signatures(pki: Pki) -> None:
    report = validate_pdf(blank_pdf(), settings_with(pki))
    assert report["status"] == "no_signatures"
    assert report["signatures"] == []


def test_signed_pdf_is_valid_and_trusted(pki: Pki) -> None:
    report = validate_pdf(sign(blank_pdf(), pki), settings_with(pki))
    assert report["status"] == "valid"
    [signature] = report["signatures"]
    assert signature["signerName"] == "PRIYA S RAGHAVAN"
    assert signature["intact"] is True
    assert signature["trusted"] is True
    assert signature["coversWholeRevision"] is True
    assert len(signature["sha256Fingerprint"]) == 64
    assert signature["fieldName"] == "Signature1"


def test_unknown_root_is_valid_but_untrusted(pki: Pki) -> None:
    report = validate_pdf(sign(blank_pdf(), pki), ValidationSettings(trust_roots=[]))
    assert report["status"] == "valid"
    assert report["signatures"][0]["trusted"] is False


def test_two_signatures_in_sequence(pki: Pki) -> None:
    twice = sign(sign(blank_pdf(), pki, "Signer1"), pki, "Signer2")
    report = validate_pdf(twice, settings_with(pki))
    assert report["status"] == "valid"
    assert [s["fieldName"] for s in report["signatures"]] == ["Signer1", "Signer2"]


def test_a_revoked_signature_stays_trusted_only_with_a_timestamp_before_it(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    plain = sign(blank_pdf(), pki)
    stamped = sign(blank_pdf(), pki, timestamper=pki.timestamper(now - timedelta(hours=2)))

    def revoked_at(at: datetime) -> None:
        with_crl(monkeypatch, pki.crl_revoking_signer(at))

    revoked_at(now - timedelta(hours=1))
    [untimed] = validate_pdf(plain, settings_with(pki))["signatures"]
    assert untimed["intact"] is True
    assert untimed["trusted"] is False
    # The timestamp proves the signature was made before the revocation.
    [older] = validate_pdf(stamped, settings_with(pki))["signatures"]
    assert older["timestamped"] is True
    assert older["trusted"] is True

    revoked_at(now - timedelta(hours=3))
    [after] = validate_pdf(stamped, settings_with(pki))["signatures"]
    assert "error" not in after
    assert after["trusted"] is False


def test_a_revocation_found_now_counts_when_checking_at_the_timestamp(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    stamped = sign(blank_pdf(), pki, timestamper=pki.timestamper(now - timedelta(hours=2)))
    # Only the check at the present finds the CRL; the fetch at the
    # timestamp's time fails.
    with_crl(monkeypatch, pki.crl_revoking_signer(now - timedelta(hours=3)), historical=False)
    [signature] = validate_pdf(stamped, settings_with(pki))["signatures"]
    assert signature["timestamped"] is True
    assert signature["trusted"] is False


def test_a_revocation_fetch_that_times_out_is_checked_without_fetching(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = validate.async_validate_pdf_signature

    async def unreachable_responder(sig: Any, signer_validation_context: Any, **kwargs: Any) -> Any:
        if signer_validation_context.fetching_allowed:
            raise TimeoutError
        return await real(sig, signer_validation_context=signer_validation_context, **kwargs)

    monkeypatch.setattr(validate, "async_validate_pdf_signature", unreachable_responder)
    signed = sign(blank_pdf(), pki)

    async def run() -> dict[str, Any]:
        async with public_fetch_session() as session:
            settings = replace(
                settings_with(pki),
                allow_fetching=True,
                fetcher_backend=AIOHttpFetcherBackend(session=session),
            )
            return await validate.validate_pdf_async(signed, settings)

    report = asyncio.run(run())
    assert report["status"] == "valid"
    [signature] = report["signatures"]
    assert signature["intact"] is True
    assert signature["trusted"] is True
    assert "error" not in signature


def test_fetching_without_the_managed_session_is_refused(pki: Pki) -> None:
    settings = replace(settings_with(pki), allow_fetching=True)
    with pytest.raises(RuntimeError, match="managed public fetch session"):
        settings.context()


def test_tampered_bytes_are_invalid(pki: Pki) -> None:
    signed = bytearray(sign(blank_pdf(), pki))
    # Flip a byte inside the signed page dictionary.
    index = signed.index(b"/MediaBox")
    signed[index + 1] = ord("N")
    report = validate_pdf(bytes(signed), settings_with(pki))
    assert report["status"] == "invalid"


def test_garbage_is_reported_not_raised(pki: Pki) -> None:
    report = validate_pdf(b"not a pdf", settings_with(pki))
    assert report["status"] == "invalid"
    assert "message" in report


def test_trust_roots_load_from_a_directory(pki: Pki, tmp_path: Path) -> None:
    pki.write_ca(tmp_path)
    (tmp_path / "notes.txt").write_text("ignored")
    (tmp_path / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nnope\n")
    roots = load_trust_roots(tmp_path)
    assert len(roots) == 1


def test_api_requires_the_token(pki: Pki) -> None:
    client = client_for(settings_with(pki))
    assert client.get("/health").json()["ok"] is True
    assert client.post("/validate", content=blank_pdf()).status_code == 401
    response = client.post(
        "/validate",
        content=sign(blank_pdf(), pki),
        headers={**AUTH, "Content-Type": "application/pdf"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "valid"


def test_prepare_adds_empty_fields_that_signers_fill(pki: Pki) -> None:
    import base64

    from keyseal_service.prepare import FieldRequest, prepare_fields

    prepared = prepare_fields(
        blank_pdf(),
        [
            FieldRequest(name="Signer_a", page=-1, box=(300, 600, 547, 672)),
            FieldRequest(name="Signer_b", page=-1, box=(300, 470, 547, 542)),
        ],
    )
    assert prepared.startswith(blank_pdf()[:8])
    # An unsigned prepared PDF has fields but no signatures yet.
    assert validate_pdf(prepared, settings_with(pki))["status"] == "no_signatures"
    # Each signer signs their own field, one incremental update at a time.
    first = sign(prepared, pki, "Signer_a")
    assert first.startswith(prepared)
    second = sign(first, pki, "Signer_b")
    assert second.startswith(first)
    report = validate_pdf(second, settings_with(pki))
    assert report["status"] == "valid"
    assert [s["fieldName"] for s in report["signatures"]] == ["Signer_a", "Signer_b"]

    client = client_for(settings_with(pki))
    response = client.post(
        "/prepare",
        json={
            "fields": [{"box": [300, 600, 547, 672], "name": "Signer_a", "page": -1}],
            "pdf": base64.b64encode(blank_pdf()).decode(),
        },
        headers=AUTH,
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    bad = client.post(
        "/prepare",
        json={
            "fields": [{"box": [0, 0, 10, 10], "name": "x", "page": 9}],
            "pdf": base64.b64encode(blank_pdf()).decode(),
        },
        headers=AUTH,
    )
    assert bad.status_code == 422


def test_a_system_root_or_unknown_ca_is_not_a_configured_root(pki: Pki) -> None:
    other = Pki()
    report = validate_pdf(sign(blank_pdf(), other), settings_with(pki))
    assert report["signatures"][0]["trusted"] is False


def test_certificate_check_needs_a_configured_root(pki: Pki) -> None:
    client = client_for(settings_with(pki))
    auth = AUTH
    other = Pki()

    def check(owner: Pki) -> bool:
        der = owner.signer_cert.public_bytes(serialization.Encoding.DER)
        ca = owner.ca.public_bytes(serialization.Encoding.DER)
        response = client.post(
            "/certificate",
            headers=auth,
            json={"certificate": b64(der), "chain": [b64(ca)]},
        )
        assert response.status_code == 200
        return response.json()["trusted"]

    assert check(pki) is True
    assert check(other) is False
    # Chains to the root, but may only encrypt, so it can't sign for us.
    encryption = client.post(
        "/certificate",
        headers=auth,
        json={
            "certificate": b64(pki.encryption_cert().public_bytes(serialization.Encoding.DER)),
            "chain": [b64(pki.ca.public_bytes(serialization.Encoding.DER))],
        },
    )
    assert encryption.json()["trusted"] is False
    assert (
        client.post("/certificate", headers=auth, json={"certificate": "nope"}).status_code
        == 400
    )


# ── Income Tax Department signatures ────────────────────────────────────────


def _digest_info_block(key_size: int, digest_info: bytes) -> bytes:
    return b"\x00\x01" + b"\xff" * (key_size - 3 - len(digest_info)) + b"\x00" + digest_info


def _raw_rsa_sign(pki: Pki, block: bytes) -> bytes:
    """Signs a padded PKCS#1 block as is, as a signer that builds its own DigestInfo would."""
    numbers = pki.signer_key.private_numbers()
    n = numbers.public_numbers.n
    size = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(block, "big"), numbers.d, n).to_bytes(size, "big")


def _without_null(digest: bytes) -> bytes:
    body = bytes.fromhex("300b0609608648016503040201") + bytes([0x04, len(digest)]) + digest
    return bytes([0x30, len(body)]) + body


def _check(pki: Pki, signature: bytes, data: bytes) -> None:
    from asn1crypto import algos, keys

    spki = keys.PublicKeyInfo.load(
        pki.signer_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    validate.SIGNATURE_VALIDATOR.validate_signature(
        signature,
        data,
        spki,
        algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
    )


def test_accepts_a_digest_info_without_null_parameters(pki: Pki) -> None:
    import hashlib

    data = b"signed attributes"
    size = pki.signer_key.key_size // 8
    signature = _raw_rsa_sign(pki, _digest_info_block(size, _without_null(hashlib.sha256(data).digest())))
    _check(pki, signature, data)


def test_still_refuses_other_digest_info_encodings(pki: Pki) -> None:
    import hashlib

    from cryptography.exceptions import InvalidSignature

    data = b"signed attributes"
    size = pki.signer_key.key_size // 8
    digest = hashlib.sha256(data).digest()
    variants = {
        # The right encoding over different data.
        "other data": _without_null(hashlib.sha256(b"other").digest()),
        # Trailing bytes after the digest.
        "trailing bytes": _without_null(digest) + b"\x00",
        # SHA-1's identifier with a SHA-256 signature algorithm.
        "wrong hash": bytes.fromhex("3021300906052b0e03021a0414") + hashlib.sha1(data).digest(),
    }
    for name, digest_info in variants.items():
        signature = _raw_rsa_sign(pki, _digest_info_block(size, digest_info))
        with pytest.raises(InvalidSignature):
            _check(pki, signature, data)
        assert name


def test_intermediates_complete_a_chain_the_pdf_leaves_out(tmp_path: Path) -> None:
    from asn1crypto import keys
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    from .conftest import _asn1, _cert, _name

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert(_name("Test CCA Root"), _name("Test CCA Root"), root_key.public_key(), root_key, ca=True)
    sub_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sub = _cert(_name("Test Sub CA"), _name("Test CCA Root"), sub_key.public_key(), root_key, ca=True)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert(_name("PRAVEEN KARANTH"), _name("Test Sub CA"), leaf_key.public_key(), sub_key, ca=False)
    signer = signers.SimpleSigner(
        signing_cert=_asn1(leaf),
        signing_key=keys.PrivateKeyInfo.load(
            leaf_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        ),
        # The PDF carries no chain, as the department's don't.
        cert_registry=SimpleCertificateStore.from_certs([]),
    )
    import io

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    signed = signers.sign_pdf(
        IncrementalPdfFileWriter(io.BytesIO(blank_pdf())),
        signers.PdfSignatureMetadata(field_name="Signature1"),
        signer=signer,
    ).getvalue()

    without = validate_pdf(signed, ValidationSettings(trust_roots=[_asn1(root)]))
    assert without["signatures"][0]["intact"] is True
    assert without["signatures"][0]["trusted"] is False

    (tmp_path / "sub.pem").write_bytes(sub.public_bytes(serialization.Encoding.PEM))
    with_sub = validate_pdf(
        signed,
        ValidationSettings(trust_roots=[_asn1(root)], intermediates=load_trust_roots(tmp_path)),
    )
    assert with_sub["signatures"][0]["trusted"] is True

    # An intermediate is never a trust anchor on its own.
    only_sub = validate_pdf(
        signed, ValidationSettings(trust_roots=[], intermediates=load_trust_roots(tmp_path))
    )
    assert only_sub["signatures"][0]["trusted"] is False


def test_shipped_intermediates_chain_to_the_shipped_root() -> None:
    from cryptography import x509 as cx509

    from keyseal_service.settings import TRUST as here

    def load(path: Path) -> cx509.Certificate:
        data = path.read_bytes()
        if data.startswith(b"-----BEGIN"):
            return cx509.load_pem_x509_certificate(data)
        return cx509.load_der_x509_certificate(data)

    root = load(here / "roots" / "cca-india-2022.cer")
    ca = load(here / "intermediates" / "emudhra-ca-2022.crt")
    sub = load(here / "intermediates" / "emudhra-sub-ca-class-3-organisation-2022.crt")
    ca.verify_directly_issued_by(root)
    sub.verify_directly_issued_by(ca)


def _with_looping_widget(pdf: bytes) -> bytes:
    """`pdf` with a widget whose /Parent is itself appended as a revision."""
    import io

    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    page = writer.find_page_for_modification(0)[0].get_object()
    widget = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Annot"),
            generic.NameObject("/Subtype"): generic.NameObject("/Widget"),
            generic.NameObject("/Rect"): generic.ArrayObject(
                [generic.NumberObject(n) for n in (0, 0, 10, 10)]
            ),
            generic.NameObject("/T"): generic.TextStringObject("loop"),
        }
    )
    ref = writer.add_object(widget)
    widget[generic.NameObject("/Parent")] = ref
    annots = list(page["/Annots"]) if "/Annots" in page else []
    page[generic.NameObject("/Annots")] = generic.ArrayObject([*annots, ref])
    writer.update_container(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_a_looping_field_tree_counts_as_changed_instead_of_hanging(pki: Pki) -> None:
    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.misc import PdfReadError

    looping = generic.DictionaryObject({generic.NameObject("/T"): generic.TextStringObject("a")})
    looping[generic.NameObject("/Parent")] = looping
    with pytest.raises(PdfReadError):
        validate._field_name(looping)
    deep = generic.DictionaryObject()
    for _ in range(validate.MAX_FIELD_DEPTH + 1):
        deep = generic.DictionaryObject({generic.NameObject("/Parent"): deep})
    with pytest.raises(PdfReadError):
        validate._field_name(deep)

    base = sign(blank_pdf(), pki)
    report = validate_pdf(_with_looping_widget(base), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "OTHER"


def test_any_parser_failure_is_reported_not_raised(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_: object, **__: object) -> None:
        raise AttributeError("read_data")

    monkeypatch.setattr(validate, "PdfFileReader", explode)
    report = validate_pdf(sign(blank_pdf(), pki), settings_with(pki))
    assert report["status"] == "invalid"
    assert report["message"] == "Not a readable PDF: AttributeError"


def test_the_token_needs_the_bearer_scheme_and_bodies_a_size(pki: Pki) -> None:
    client = client_for(settings_with(pki))
    for header in (TOKEN, f"Basic {TOKEN}", f"Bearer{TOKEN}"):
        response = client.post("/validate", content=blank_pdf(), headers={"Authorization": header})
        assert response.status_code == 401, header
    too_big = client.post(
        "/validate",
        content=b"",
        headers={**AUTH, "Content-Length": str(MAX_BODY_BYTES + 1)},
    )
    assert too_big.status_code == 413
    nan = client.post(
        "/prepare",
        headers=AUTH,
        json={"pdf": b64(blank_pdf()), "fields": [{"name": "a", "page": 0, "box": [0, 0, "NaN", 1]}]},
    )
    assert nan.status_code == 422
    huge = client.post(
        "/prepare",
        headers=AUTH,
        json={"pdf": b64(blank_pdf()), "fields": [{"name": "a", "page": 0, "box": [0, 0, 1e300, 1]}]},
    )
    assert huge.status_code == 422
