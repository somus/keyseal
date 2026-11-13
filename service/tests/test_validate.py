from __future__ import annotations

import asyncio
import io
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend

from keyseal_service import app as app_module
from fastapi.testclient import TestClient

from keyseal_service import remote_sign, validate
from keyseal_service.app import MAX_BODY_BYTES
from keyseal_service.fetching import public_fetch_session
from keyseal_service.validate import ValidationSettings, load_trust_roots, validate_pdf

from .conftest import AUTH, TOKEN, Pki, _asn1, blank_pdf, client_for, misstamping, sign
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
    assert signature["timestamped"] is False
    assert signature["timestampValid"] is None


def test_a_timestamp_for_another_digest_makes_the_signature_invalid(pki: Pki) -> None:
    good = pki.timestamper(datetime.now(UTC))
    [stamped] = validate_pdf(sign(blank_pdf(), pki, timestamper=good), settings_with(pki))[
        "signatures"
    ]
    assert stamped["timestampValid"] is True

    misstamped = sign(blank_pdf(), pki, timestamper=misstamping(pki.timestamper(datetime.now(UTC))))
    report = validate_pdf(misstamped, settings_with(pki))
    assert report["status"] == "invalid"
    [signature] = report["signatures"]
    assert signature["intact"] is True
    assert signature["timestamped"] is True
    assert signature["timestampValid"] is False


def test_revocation_counts_as_checked_only_with_data_for_the_signer(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed = sign(blank_pdf(), pki)
    # The signer's certificate names a CRL, and without fetching none is found.
    [unchecked] = validate_pdf(signed, settings_with(pki))["signatures"]
    assert unchecked["trusted"] is True
    assert unchecked["revocationChecked"] is False

    with_crl(monkeypatch, pki.crl())
    [checked] = validate_pdf(signed, settings_with(pki))["signatures"]
    assert checked["trusted"] is True
    assert checked["revocationChecked"] is True


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
        with_crl(monkeypatch, pki.crl(at))

    revoked_at(now - timedelta(hours=1))
    [untimed] = validate_pdf(plain, settings_with(pki))["signatures"]
    assert untimed["intact"] is True
    assert untimed["trusted"] is False
    assert untimed["revocationChecked"] is False
    # The timestamp proves the signature was made before the revocation.
    [older] = validate_pdf(stamped, settings_with(pki))["signatures"]
    assert older["timestamped"] is True
    assert older["timestampValid"] is True
    assert older["trusted"] is True
    assert older["revocationChecked"] is True

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
    with_crl(monkeypatch, pki.crl(now - timedelta(hours=3)), historical=False)
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


def test_a_certificate_whose_revocation_fetch_times_out_is_checked_without_fetching(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = validate.CertificateValidator

    class UnreachableResponder(real):  # type: ignore[misc, valid-type]
        async def async_validate_path(self) -> Any:
            if self._context.fetching_allowed:
                raise TimeoutError
            return await super().async_validate_path()

    monkeypatch.setattr(validate, "CertificateValidator", UnreachableResponder)

    async def run() -> bool:
        async with public_fetch_session() as session:
            settings = replace(
                settings_with(pki),
                allow_fetching=True,
                fetcher_backend=AIOHttpFetcherBackend(session=session),
            )
            return await validate.certificate_trusted(
                _asn1(pki.signer_cert), [pki.ca_asn1], settings
            )

    assert asyncio.run(run()) == (True, False)


def test_fetching_without_the_managed_session_is_refused(pki: Pki) -> None:
    settings = replace(settings_with(pki), allow_fetching=True)
    with pytest.raises(RuntimeError, match="public fetch session"):
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

    def check(owner: Pki, trailing: bytes = b"") -> dict[str, bool]:
        der = owner.signer_cert.public_bytes(serialization.Encoding.DER)
        ca = owner.ca.public_bytes(serialization.Encoding.DER)
        response = client.post(
            "/certificate",
            headers=auth,
            json={"certificate": b64(der + trailing), "chain": [b64(ca)]},
        )
        assert response.status_code == 200
        return response.json()

    assert check(pki) == {"revocationChecked": False, "trusted": True}
    assert check(other) == {"revocationChecked": False, "trusted": False}
    # Bytes after the certificate, such as another one in PEM, are refused
    # rather than ignored.
    pem = other.signer_cert.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(AssertionError):
        check(pki, b"\n" + pem)
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


def test_certificate_check_applies_the_key_usage_asked_for(pki: Pki) -> None:
    client = client_for(settings_with(pki))
    ca = b64(pki.ca.public_bytes(serialization.Encoding.DER))

    def check(cert: Any, **policy: str) -> Any:
        der = cert.public_bytes(serialization.Encoding.DER)
        return client.post(
            "/certificate", headers=AUTH, json={"certificate": b64(der), "chain": [ca], **policy}
        )

    def trusted(cert: Any, **policy: str) -> bool:
        response = check(cert, **policy)
        assert response.status_code == 200
        return response.json()["trusted"]

    digital_signature = pki.signing_cert({"digital_signature"})
    non_repudiation = pki.signing_cert({"content_commitment"})
    no_key_usage = pki.signing_cert(None)
    assert trusted(digital_signature) is False
    assert trusted(digital_signature, keyUsage="nonRepudiation") is False
    assert trusted(digital_signature, keyUsage="digitalSignature") is True
    assert trusted(non_repudiation) is True
    assert trusted(non_repudiation, keyUsage="digitalSignature") is True
    assert trusted(no_key_usage) is False
    assert trusted(no_key_usage, keyUsage="digitalSignature") is False
    # A CA's certificate never signs for us, whatever key usage it asserts.
    ca_cert = pki.signing_cert(
        {"digital_signature", "content_commitment", "key_cert_sign"}, ca=True
    )
    assert trusted(ca_cert, keyUsage="digitalSignature") is False
    assert check(digital_signature, keyUsage="keyAgreement").status_code == 422


def test_validation_trusts_a_signer_with_the_key_usage_asked_for(pki: Pki) -> None:
    signed = sign(blank_pdf(), pki, cert=pki.signing_cert({"digital_signature"}))
    client = client_for(settings_with(pki))

    def signature(query: str = "") -> dict[str, Any]:
        response = client.post(f"/validate{query}", headers=AUTH, content=signed)
        assert response.status_code == 200
        [sig] = response.json()["signatures"]
        return sig

    assert signature()["intact"] is True
    assert signature()["trusted"] is False
    assert signature("?keyUsage=nonRepudiation")["trusted"] is False
    assert signature("?keyUsage=digitalSignature")["trusted"] is True
    assert client.post("/validate?keyUsage=any", headers=AUTH, content=signed).status_code == 422
    no_key_usage = sign(blank_pdf(), pki, cert=pki.signing_cert(None))
    report = validate_pdf(no_key_usage, settings_with(pki), key_usage="digitalSignature")
    assert report["signatures"][0]["trusted"] is False


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


def test_an_oversized_rsa_key_never_reaches_the_exponentiation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from asn1crypto import algos, keys
    from pyhanko_certvalidator.sig_validate import DEFAULT_VALIDATION_CONTEXT

    def refuse(*_: object) -> int:
        raise AssertionError("pow() ran on an oversized key")

    monkeypatch.setattr(validate, "pow", refuse, raising=False)
    algorithm = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    for n, e in [((1 << 20000) | 1, 65537), ((1 << 4095) | 1, (1 << 4000) | 1)]:
        spki = keys.PublicKeyInfo(
            {
                "algorithm": {"algorithm": "rsa"},
                "public_key": keys.RSAPublicKey({"modulus": n, "public_exponent": e}),
            }
        )
        signature = b"\x01" * ((n.bit_length() + 7) // 8)
        assert not validate._pkcs1_without_null(
            signature, b"data", spki, algorithm, DEFAULT_VALIDATION_CONTEXT
        )


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


def test_a_widget_sharing_objects_is_digested_once_per_object(pki: Pki) -> None:
    import io

    from pyhanko.pdf_utils import generic
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    base = sign(blank_pdf(), pki)
    writer = IncrementalPdfFileWriter(io.BytesIO(base))
    # Each array refers twice to the next: 2**60 paths, 60 objects.
    node = writer.add_object(generic.ArrayObject())
    for _ in range(60):
        node = writer.add_object(generic.ArrayObject([node, node]))
    widget = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Annot"),
            generic.NameObject("/Subtype"): generic.NameObject("/Widget"),
            generic.NameObject("/Rect"): generic.ArrayObject(
                [generic.NumberObject(n) for n in (0, 0, 10, 10)]
            ),
            generic.NameObject("/T"): generic.TextStringObject("shared"),
            generic.NameObject("/MK"): node,
        }
    )
    page = writer.find_page_for_modification(0)[0].get_object()
    annots = list(page["/Annots"]) if "/Annots" in page else []
    page[generic.NameObject("/Annots")] = generic.ArrayObject([*annots, writer.add_object(widget)])
    writer.update_container(page)
    out = io.BytesIO()
    writer.write(out)

    report = validate_pdf(out.getvalue(), settings_with(pki), len(base))
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


def test_a_validation_does_not_hold_up_other_requests(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    started, release = threading.Event(), threading.Event()
    released: list[bool] = []

    async def busy(*_: Any) -> dict[str, Any]:
        # Blocks the way pyHanko's inline hashing does, until /health answers.
        started.set()
        released.append(release.wait(timeout=5))
        return {}

    monkeypatch.setattr(app_module, "validate_pdf_async", busy)
    # Inside `with`, every request runs on the client's one event loop.
    with client_for(settings_with(pki)) as client:
        validating = threading.Thread(
            target=lambda: client.post("/validate", content=blank_pdf(), headers=AUTH)
        )
        validating.start()
        assert started.wait(timeout=5)
        assert client.get("/health").status_code == 200
        release.set()
        validating.join()
    assert released == [True]


def test_a_pdf_with_too_many_signatures_is_refused(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    twice = sign(sign(blank_pdf(), pki, "Signer1"), pki, "Signer2")
    monkeypatch.setattr(validate, "MAX_SIGNATURES", 2)
    assert validate_pdf(twice, settings_with(pki))["status"] == "valid"
    monkeypatch.setattr(validate, "MAX_SIGNATURES", 1)
    with pytest.raises(validate.ValidationLimitError):
        validate_pdf(twice, settings_with(pki))
    with client_for(settings_with(pki)) as client:
        response = client.post("/validate", content=twice, headers=AUTH)
    assert response.status_code == 422
    assert response.json() == {"detail": "More than 1 signatures"}


def test_a_validation_past_its_budget_is_refused_and_stops(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    stopped = threading.Event()

    async def unanswered_fetch(*_: Any) -> Any:
        try:
            await asyncio.sleep(60)
        finally:
            stopped.set()

    monkeypatch.setattr(validate, "_check_signature", unanswered_fetch)
    monkeypatch.setattr(validate, "VALIDATION_BUDGET_SECONDS", 0.1)
    with client_for(settings_with(pki)) as client:
        response = client.post("/validate", content=sign(blank_pdf(), pki), headers=AUTH)
    assert response.status_code == 422
    assert response.json() == {"detail": "Validation took longer than 0.1 seconds"}
    # The worker thread's loop cancelled the work rather than leaving it running.
    assert stopped.is_set()


def _unanswered(stopped: threading.Event) -> Any:
    async def unanswered(*_: Any, **__: Any) -> Any:
        try:
            await asyncio.sleep(60)
        finally:
            stopped.set()

    return unanswered


def _with_local_tsa(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(
        app_module.timestamps, "HTTPTimeStamper", lambda _url: pki.timestamper(datetime.now(UTC))
    )
    return client_for(settings_with(pki), "https://tsa.invalid")


def test_a_certificate_check_past_its_budget_stops_and_may_be_retried(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    stopped = threading.Event()

    class UnansweredValidator:
        def __init__(self, *_: Any, **__: Any) -> None:
            pass

        async_validate_path = _unanswered(stopped)

    monkeypatch.setattr(validate, "CertificateValidator", UnansweredValidator)
    monkeypatch.setattr(validate, "VALIDATION_BUDGET_SECONDS", 0.1)
    with client_for(settings_with(pki)) as client:
        response = client.post(
            "/certificate",
            headers=AUTH,
            json={"certificate": b64(pki.signer_cert.public_bytes(serialization.Encoding.DER))},
        )
    assert response.status_code == 504
    assert response.json() == {"detail": "The certificate check took longer than 0.1 seconds"}
    assert stopped.is_set()


@pytest.mark.parametrize(
    ("path", "slow", "message"),
    [
        (
            "/finalize",
            (remote_sign, "async_add_validation_info"),
            "Finalising took longer than 0.1 seconds",
        ),
        (
            "/retimestamp",
            (remote_sign.signers.PdfTimeStamper, "async_update_archival_timestamp_chain"),
            "Timestamping took longer than 0.1 seconds",
        ),
    ],
)
def test_long_term_validation_past_its_budget_is_refused_and_stops(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, path: str, slow: tuple[Any, str], message: str
) -> None:
    stopped = threading.Event()
    monkeypatch.setattr(*slow, _unanswered(stopped))
    monkeypatch.setattr(validate, "VALIDATION_BUDGET_SECONDS", 0.1)
    with _with_local_tsa(pki, monkeypatch) as client:
        response = client.post(path, content=sign(blank_pdf(), pki), headers=AUTH)
    assert response.status_code == 422
    assert response.json() == {"detail": message}
    assert stopped.is_set()


def test_finalising_a_pdf_with_too_many_signatures_is_refused(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    twice = sign(sign(blank_pdf(), pki, "Signer1"), pki, "Signer2")
    monkeypatch.setattr(validate, "MAX_SIGNATURES", 1)
    with _with_local_tsa(pki, monkeypatch) as client:
        response = client.post("/finalize", content=twice, headers=AUTH)
    assert response.status_code == 422
    assert response.json() == {"detail": "More than 1 signatures"}


def test_long_term_archive_finalises_and_retimestamps_offline(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The test root's CRL stands in for a fetch; the TSA is a local one under the same root.
    with_crl(monkeypatch, pki.crl())
    signed = sign(blank_pdf(), pki, timestamper=pki.timestamper(datetime.now(UTC)))
    with _with_local_tsa(pki, monkeypatch) as client:
        finalised = client.post("/finalize", content=signed, headers=AUTH)
        assert finalised.status_code == 200
        archived = client.post("/retimestamp", content=finalised.content, headers=AUTH)
        assert archived.status_code == 200
    assert finalised.content.startswith(signed)
    assert archived.content.startswith(finalised.content)

    reader = PdfFileReader(io.BytesIO(archived.content))
    dss = DocumentSecurityStore.read_dss(reader)
    assert len(dss.crls) >= 1
    assert len(dss.certs) >= 2  # the signer's root and the TSA's certificate

    report = validate_pdf(archived.content, settings_with(pki))
    assert report["status"] == "valid"
    [signature] = report["signatures"]
    assert signature["trusted"] is True
    assert signature["timestampValid"] is True
    assert signature["revocationChecked"] is True
    assert [(t["intact"], t["trusted"]) for t in report["documentTimestamps"]] == [
        (True, True),
        (True, True),
    ]
