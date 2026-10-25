from __future__ import annotations

import asyncio
import base64
import io
import json
import os
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from fastapi.testclient import TestClient
from pyhanko.sign import timestamps

from keyseal_service.prepare import FieldRequest, prepare_fields
from keyseal_service.remote_sign import (
    RemoteSignError,
    UnsupportedKeyError,
    finalize,
    finish,
    start,
)
from keyseal_service.app import create_app
from keyseal_service.appearance import SignedByStamp, SignedByStampStyle, reason_lines
from keyseal_service.settings import Settings
from keyseal_service.validate import ValidationSettings, validate_pdf

from .conftest import AUTH, Pki, blank_pdf, client_for


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


def begin(pdf: bytes, field: str, cert: str, chain: list[str], rsa_padding: str = "pkcs1"):
    return start(pdf, field, cert, chain, SignedByStampStyle(), rsa_padding)  # type: ignore[arg-type]


def token_sign(pki: Pki, data: bytes) -> bytes:
    """What the helper does on the token: RSA PKCS#1 v1.5 over SHA-256."""
    return pki.signer_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def cert_b64(pki: Pki) -> str:
    return b64(pki.signer_cert.public_bytes(serialization.Encoding.DER))


def ca_b64(pki: Pki) -> str:
    return b64(pki.ca.public_bytes(serialization.Encoding.DER))


def test_deferred_signing_produces_a_valid_signature_in_the_field(pki: Pki) -> None:
    pdf = prepared()
    started = asyncio.run(begin(pdf, "Signer_a", cert_b64(pki), [ca_b64(pki)]))
    assert started.signature_algorithm == "rsa-pkcs1-v1_5"
    signed = asyncio.run(finish(started.state, token_sign(pki, started.to_sign), None))
    assert signed.startswith(pdf)
    report = validate_pdf(signed, ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert report["status"] == "valid"
    [sig] = report["signatures"]
    assert sig["fieldName"] == "Signer_a"
    assert sig["signerName"] == "PRIYA S RAGHAVAN"
    assert sig["trusted"] is True


@pytest.mark.parametrize(
    ("curve", "digest_algorithm", "digest"),
    [(ec.SECP256R1(), "sha256", hashes.SHA256()), (ec.SECP384R1(), "sha384", hashes.SHA384())],
)
def test_deferred_ecdsa_signing_produces_a_valid_signature(
    pki: Pki, curve: ec.EllipticCurve, digest_algorithm: str, digest: hashes.HashAlgorithm
) -> None:
    key, cert = pki.ec_signer(curve)
    pdf = prepared()
    started = asyncio.run(
        begin(pdf, "Signer_a", b64(cert.public_bytes(serialization.Encoding.DER)), [ca_b64(pki)])
    )
    assert started.digest_algorithm == digest_algorithm
    assert started.signature_algorithm == "ecdsa"
    # What the helper does: hash, CKM_ECDSA on the token, DER-encode r and s.
    signed = asyncio.run(finish(started.state, key.sign(started.to_sign, ec.ECDSA(digest)), None))
    report = validate_pdf(signed, ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert report["status"] == "valid"
    [sig] = report["signatures"]
    assert sig["fieldName"] == "Signer_a"
    assert sig["trusted"] is True


def test_deferred_rsa_pss_signing_produces_a_valid_signature(pki: Pki) -> None:
    started = asyncio.run(begin(prepared(), "Signer_a", cert_b64(pki), [ca_b64(pki)], "pss"))
    assert started.signature_algorithm == "rsa-pss"
    # What the helper does with CKM_SHA256_RSA_PKCS_PSS: MGF1-SHA256, 32-byte salt.
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    signed = asyncio.run(
        finish(started.state, pki.signer_key.sign(started.to_sign, pss, hashes.SHA256()), None)
    )
    report = validate_pdf(signed, ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert report["status"] == "valid"
    assert report["signatures"][0]["trusted"] is True
    [sig] = PdfFileReader(io.BytesIO(signed)).embedded_signatures
    params = sig.signer_info["signature_algorithm"]["parameters"]
    assert sig.signer_info["signature_algorithm"].signature_algo == "rsassa_pss"
    assert params["salt_length"].native == 32
    assert params["mask_gen_algorithm"]["parameters"]["algorithm"].native == "sha256"


def test_a_pkcs1_signature_is_refused_when_pss_was_asked_for(pki: Pki) -> None:
    started = asyncio.run(begin(prepared(), "Signer_a", cert_b64(pki), [ca_b64(pki)], "pss"))
    with pytest.raises(RemoteSignError, match="doesn't match the certificate"):
        asyncio.run(finish(started.state, token_sign(pki, started.to_sign), None))


def test_raw_ecdsa_signature_is_refused(pki: Pki) -> None:
    key, cert = pki.ec_signer(ec.SECP256R1())
    started = asyncio.run(
        begin(prepared(), "Signer_a", b64(cert.public_bytes(serialization.Encoding.DER)), [])
    )
    r, s = decode_dss_signature(key.sign(started.to_sign, ec.ECDSA(hashes.SHA256())))
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    with pytest.raises(RemoteSignError, match="DER ECDSA-Sig-Value"):
        asyncio.run(finish(started.state, raw, None))


def test_an_unsupported_curve_is_refused(pki: Pki) -> None:
    _key, cert = pki.ec_signer(ec.SECP521R1())
    with pytest.raises(UnsupportedKeyError, match="P-256 and P-384"):
        asyncio.run(
            begin(prepared(), "Signer_a", b64(cert.public_bytes(serialization.Encoding.DER)), [])
        )


def test_two_signers_sign_in_turn(pki: Pki) -> None:
    first_start = asyncio.run(begin(prepared(), "Signer_a", cert_b64(pki), [ca_b64(pki)]))
    first = asyncio.run(finish(first_start.state, token_sign(pki, first_start.to_sign), None))
    second_start = asyncio.run(begin(first, "Signer_b", cert_b64(pki), [ca_b64(pki)]))
    second = asyncio.run(
        finish(second_start.state, token_sign(pki, second_start.to_sign), None)
    )
    report = validate_pdf(second, ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert report["status"] == "valid"
    assert [s["fieldName"] for s in report["signatures"]] == ["Signer_a", "Signer_b"]


def test_a_wrong_signature_is_refused(pki: Pki) -> None:
    started = asyncio.run(begin(prepared(), "Signer_a", cert_b64(pki), [ca_b64(pki)]))
    with pytest.raises(RemoteSignError, match="doesn't match the certificate"):
        asyncio.run(finish(started.state, token_sign(pki, b"something else"), None))


def test_a_missing_or_filled_field_is_refused(pki: Pki) -> None:
    with pytest.raises(RemoteSignError, match="no empty field"):
        asyncio.run(begin(prepared(), "Nobody", cert_b64(pki), [ca_b64(pki)]))


@pytest.mark.skipif(
    os.environ.get("SIGNING_NETWORK_TESTS") != "1",
    reason="needs the DigiCert TSA; set SIGNING_NETWORK_TESTS=1",
)
def test_timestamped_signature_and_long_term_finalisation(pki: Pki) -> None:
    tsa = timestamps.HTTPTimeStamper("http://timestamp.digicert.com")
    started = asyncio.run(begin(prepared(), "Signer_a", cert_b64(pki), [ca_b64(pki)]))
    signed = asyncio.run(finish(started.state, token_sign(pki, started.to_sign), tsa))
    settings = ValidationSettings(trust_roots=[pki.ca_asn1])
    assert validate_pdf(signed, settings)["signatures"][0]["timestamped"] is True
    final = asyncio.run(finalize(signed, tsa, settings.context()))
    assert final.startswith(signed)
    assert validate_pdf(final, settings)["status"] == "valid"


def test_api_signs_in_two_steps(pki: Pki) -> None:
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    auth = AUTH
    started = client.post(
        "/sign/start",
        headers=auth,
        json={
            "certificate": cert_b64(pki),
            "chain": [ca_b64(pki)],
            "fieldName": "Signer_b",
            "pdf": b64(prepared()),
        },
    )
    assert started.status_code == 200
    body = started.json()
    assert body["digestAlgorithm"] == "sha256"
    assert body["signatureAlgorithm"] == "rsa-pkcs1-v1_5"
    signature = token_sign(pki, base64.b64decode(body["toSign"]))
    finished = client.post(
        "/sign/finish",
        headers=auth,
        json={"signature": b64(signature), "state": body["state"]},
    )
    assert finished.status_code == 200
    report = validate_pdf(finished.content, ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert report["status"] == "valid"
    bad = client.post(
        "/sign/finish",
        headers=auth,
        json={"signature": b64(b"x" * 256), "state": body["state"]},
    )
    assert bad.status_code == 422
    assert client.post("/finalize", headers=auth, content=b"%PDF").status_code == 503
    _key, p521 = pki.ec_signer(ec.SECP521R1())
    p521_b64 = b64(p521.public_bytes(serialization.Encoding.DER))
    unsupported = client.post(
        "/sign/start",
        headers=auth,
        json={"certificate": p521_b64, "fieldName": "Signer_a", "pdf": b64(prepared())},
    )
    assert unsupported.status_code == 400
    assert "P-256 and P-384" in unsupported.json()["detail"]
    refused = client.post("/certificate", headers=auth, json={"certificate": p521_b64})
    assert refused.status_code == 400
    pss = client.post(
        "/sign/start",
        headers=auth,
        json={
            "certificate": cert_b64(pki),
            "fieldName": "Signer_a",
            "pdf": b64(prepared()),
            "rsaPadding": "pss",
        },
    )
    assert pss.status_code == 200
    assert pss.json()["signatureAlgorithm"] == "rsa-pss"
    pss_signature = pki.signer_key.sign(
        base64.b64decode(pss.json()["toSign"]),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    pss_finished = client.post(
        "/sign/finish",
        headers=auth,
        json={"signature": b64(pss_signature), "state": pss.json()["state"]},
    )
    assert pss_finished.status_code == 200


def test_an_unreadable_pdf_is_refused_not_a_service_failure(pki: Pki) -> None:
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    response = client.post(
        "/sign/start",
        headers=AUTH,
        json={"certificate": cert_b64(pki), "fieldName": "Signer_a", "pdf": b64(b"not a pdf")},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Not a readable PDF"


OTHER_TOKEN = "Other-token-0123456789-abcdefghijk"


def _tampered(state: str, change: Callable[[dict[str, Any]], None]) -> str:
    members = json.loads(state)
    change(members)
    return json.dumps(members)


def test_sign_finish_refuses_a_state_it_did_not_issue(pki: Pki) -> None:
    settings = ValidationSettings(trust_roots=[pki.ca_asn1])
    client = client_for(settings)
    started = client.post(
        "/sign/start",
        headers=AUTH,
        json={
            "certificate": cert_b64(pki),
            "chain": [ca_b64(pki)],
            "fieldName": "Signer_a",
            "pdf": b64(prepared()),
        },
    ).json()
    state = started["state"]
    # @keyseal/server reads the prepared PDF from the state.
    assert base64.b64decode(json.loads(state)["output"]).startswith(b"%PDF")
    signature = b64(token_sign(pki, base64.b64decode(started["toSign"])))

    def finish_with(
        state: str, using: TestClient = client, token: str = AUTH["Authorization"]
    ) -> Any:
        return using.post(
            "/sign/finish",
            headers={"Authorization": token},
            json={"signature": signature, "state": state},
        )

    other_pdf = b64(blank_pdf())
    other = TestClient(create_app(Settings(token=OTHER_TOKEN, tsa_url=None, validation=settings)))
    refusals = [
        finish_with(_tampered(state, lambda m: m.update(output=other_pdf))),
        finish_with(_tampered(state, lambda m: m.update(reservedStart=m["reservedStart"] + 1))),
        finish_with(_tampered(state, lambda m: m.pop("mac"))),
        finish_with(_tampered(state, lambda m: m.update(mac="0" * 64))),
        # A MAC under another service's token.
        finish_with(state, using=other, token=f"Bearer {OTHER_TOKEN}"),
    ]
    for refused in refusals:
        assert refused.status_code == 422
        assert refused.json()["detail"] == "The signing state isn't one this service issued"
    # Serialised again unchanged, the state still verifies.
    assert finish_with(_tampered(state, lambda m: None)).status_code == 200
    finished = finish_with(state)
    assert finished.status_code == 200
    assert validate_pdf(finished.content, settings)["status"] == "valid"


DETAILS = {"reason": " Approved as Director ", "location": "Mumbai", "contactInfo": "cs@example.org"}


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


def test_signature_details_land_in_the_signature_dictionary(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    columns: list[str] = []
    column = SignedByStamp._column

    def recording(self, text, style, x, width):  # type: ignore[no-untyped-def]
        columns.append(text)
        return column(self, text, style, x, width)

    monkeypatch.setattr(SignedByStamp, "_column", recording)
    settings = ValidationSettings(trust_roots=[pki.ca_asn1])
    client = client_for(settings)
    started = _start_with(client, pki, **DETAILS)
    assert started.status_code == 200
    body = started.json()
    finished = client.post(
        "/sign/finish",
        headers=AUTH,
        json={
            "signature": b64(token_sign(pki, base64.b64decode(body["toSign"]))),
            "state": body["state"],
        },
    )
    assert finished.status_code == 200
    assert validate_pdf(finished.content, settings)["status"] == "valid"
    sig = PdfFileReader(io.BytesIO(finished.content)).embedded_signatures[0].sig_object
    assert sig["/Reason"] == "Approved as Director"
    assert sig["/Location"] == "Mumbai"
    assert sig["/ContactInfo"] == "cs@example.org"
    assert columns[1].splitlines()[2] == "Reason: Approved as Director"


def test_signature_details_are_covered_by_the_state_mac(pki: Pki) -> None:
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    started = _start_with(client, pki, **DETAILS).json()
    output = base64.b64decode(json.loads(started["state"])["output"])
    assert b"(Approved as Director)" in output
    forged = b64(output.replace(b"(Approved as Director)", b"(Rejected as Director)"))
    refused = client.post(
        "/sign/finish",
        headers=AUTH,
        json={
            "signature": b64(token_sign(pki, base64.b64decode(started["toSign"]))),
            "state": _tampered(started["state"], lambda m: m.update(output=forged)),
        },
    )
    assert refused.status_code == 422
    assert refused.json()["detail"] == "The signing state isn't one this service issued"


@pytest.mark.parametrize(
    "details",
    [
        {"reason": "x" * 201},
        {"location": "   "},
        {"contactInfo": "a\nb"},
        {"reason": "Appro\u0085ved"},
    ],
)
def test_bad_signature_details_are_refused(pki: Pki, details: dict[str, str]) -> None:
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert _start_with(client, pki, **details).status_code == 422


def test_a_long_reason_wraps_to_two_lines() -> None:
    assert reason_lines("Approved") == ["Reason: Approved"]
    lines = reason_lines("Approved on behalf of the board of directors " * 5)
    assert len(lines) == 2
    assert lines[1].endswith(" ...")
    assert all(len(line) <= 33 for line in lines)
