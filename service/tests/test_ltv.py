"""/finalize and /retimestamp: revocation data and document timestamps."""

from __future__ import annotations

import asyncio
import io
import os
import threading
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import timestamps
from pyhanko.sign.validation.dss import DocumentSecurityStore

from keyseal_service import ltv, validate
from keyseal_service.appearance import SignedByStampStyle
from keyseal_service.ltv import finalize
from keyseal_service.remote_sign import finish, start

from .conftest import (
    AUTH,
    Pki,
    blank_pdf,
    ca_b64,
    cert_b64,
    certified_no_changes,
    client_with_tsas,
    prepared,
    settings_with,
    sign,
    token_sign,
    unanswered,
    validate_pdf,
    with_crl,
)


def _with_local_tsa(pki: Pki, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return client_with_tsas(
        monkeypatch, settings_with(pki), {"https://tsa.invalid": pki.timestamper(datetime.now(UTC))}
    )


@pytest.mark.parametrize(
    ("path", "slow", "message"),
    [
        (
            "/finalize",
            (ltv, "async_add_validation_info"),
            "Finalising took longer than 0.1 seconds",
        ),
        (
            "/retimestamp",
            (ltv.signers.PdfTimeStamper, "async_update_archival_timestamp_chain"),
            "Timestamping took longer than 0.1 seconds",
        ),
    ],
)
def test_long_term_validation_past_its_budget_is_refused_and_stops(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, path: str, slow: tuple[Any, str], message: str
) -> None:
    stopped = threading.Event()
    monkeypatch.setattr(*slow, unanswered(stopped))
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


@pytest.mark.skipif(
    os.environ.get("SIGNING_NETWORK_TESTS") != "1",
    reason="needs the DigiCert TSA; set SIGNING_NETWORK_TESTS=1",
)
def test_timestamped_signature_and_long_term_finalisation(pki: Pki) -> None:
    tsa = timestamps.HTTPTimeStamper("http://timestamp.digicert.com")
    started = asyncio.run(
        start(prepared(), "Signer_a", cert_b64(pki), [ca_b64(pki)], SignedByStampStyle())
    )
    signed = asyncio.run(finish(started.state, token_sign(pki, started.to_sign), tsa))
    settings = settings_with(pki)
    assert validate_pdf(signed, settings)["signatures"][0]["timestamped"] is True
    final = asyncio.run(finalize(signed, tsa, settings.context()))
    assert final.startswith(signed)
    assert validate_pdf(final, settings)["status"] == "valid"


def test_a_certified_pdf_still_takes_revocation_data_and_document_timestamps(pki: Pki) -> None:
    # PAdES lets a document certified with no changes allowed take a DSS and
    # document timestamps, so /finalize and /retimestamp don't refuse it.
    tsa = pki.timestamper(datetime.now(UTC))
    settings = settings_with(pki)
    final = asyncio.run(finalize(certified_no_changes(prepared(), pki), tsa, settings.context()))
    assert validate_pdf(final, settings)["status"] == "valid"
