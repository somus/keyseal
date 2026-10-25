from __future__ import annotations

import base64
import io
import json
from importlib.metadata import EntryPoint

import pytest
from fastapi import APIRouter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.stamp import TextStampStyle

from keyseal_service import app as app_module
from keyseal_service.settings import Settings
from keyseal_service.validate import ValidationSettings

from .conftest import AUTH, Pki, client_for
from .test_remote_sign import b64, ca_b64, cert_b64, prepared, token_sign


def plain_style() -> TextStampStyle:
    return TextStampStyle(stamp_text="Signed in test by %(signer)s")


def reason_style() -> TextStampStyle:
    return TextStampStyle(stamp_text="%(reason)s at %(location)s")


SEEN: dict[str, Settings] = {}


def extra_router(settings: Settings) -> APIRouter:
    SEEN["settings"] = settings
    router = APIRouter()

    @router.get("/extra/ping")
    def ping() -> dict[str, str]:
        return {"pong": "yes"}

    return router


def _register(monkeypatch: pytest.MonkeyPatch) -> None:
    registered = {
        app_module.STAMP_STYLES_GROUP: [
            EntryPoint("plain", f"{__name__}:plain_style", app_module.STAMP_STYLES_GROUP),
            EntryPoint("reason", f"{__name__}:reason_style", app_module.STAMP_STYLES_GROUP),
        ],
        app_module.ROUTERS_GROUP: [
            EntryPoint("extra", f"{__name__}:extra_router", app_module.ROUTERS_GROUP)
        ],
    }
    monkeypatch.setattr(app_module, "entry_points", lambda group: registered.get(group, []))


def _start(client, pki: Pki, **extra: str):
    return client.post(
        "/sign/start",
        headers=AUTH,
        json={
            "certificate": cert_b64(pki),
            "chain": [ca_b64(pki)],
            "fieldName": "Signer_a",
            "pdf": b64(prepared()),
            **extra,
        },
    )


def _appearance(pdf: bytes) -> bytes:
    sig = PdfFileReader(io.BytesIO(pdf)).embedded_signatures[0]
    return sig.sig_field["/AP"]["/N"].data


def test_a_registered_stamp_style_draws_the_signature(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(monkeypatch)
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    started = _start(client, pki, stampStyle="plain")
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
    assert b"Signed in test by" in _appearance(finished.content)


def test_a_registered_stamp_style_gets_the_signature_details(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(monkeypatch)
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    started = _start(client, pki, stampStyle="reason", reason="Approved", location="Mumbai")
    assert started.status_code == 200
    output = base64.b64decode(json.loads(started.json()["state"])["output"])
    assert b"(Approved at Mumbai) Tj" in output
    assert _start(client, pki, stampStyle="reason").status_code == 200


def test_an_unknown_stamp_style_is_refused(pki: Pki) -> None:
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    response = _start(client, pki, stampStyle="nope")
    assert response.status_code == 400
    assert "Unknown stamp style" in response.json()["detail"]


def test_a_registered_router_is_mounted_behind_the_token(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    _register(monkeypatch)
    client = client_for(ValidationSettings(trust_roots=[pki.ca_asn1]))
    assert client.get("/extra/ping").status_code == 401
    assert client.get("/extra/ping", headers=AUTH).json() == {"pong": "yes"}
    assert [c.sha256 for c in SEEN["settings"].validation.trust_roots] == [pki.ca_asn1.sha256]
