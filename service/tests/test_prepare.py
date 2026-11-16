from __future__ import annotations

import pytest

from keyseal_service.prepare import FieldRequest, prepare_fields

from .conftest import AUTH, Pki, b64, blank_pdf, client_for, settings_with, sign, validate_pdf


def test_prepare_adds_empty_fields_that_signers_fill(pki: Pki) -> None:
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
            "pdf": b64(blank_pdf()),
        },
        headers=AUTH,
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    bad = client.post(
        "/prepare",
        json={
            "fields": [{"box": [0, 0, 10, 10], "name": "x", "page": 9}],
            "pdf": b64(blank_pdf()),
        },
        headers=AUTH,
    )
    assert bad.status_code == 422


@pytest.mark.parametrize("coordinate", ["NaN", 1e300])
def test_a_coordinate_off_any_page_is_refused(pki: Pki, coordinate: object) -> None:
    response = client_for(settings_with(pki)).post(
        "/prepare",
        headers=AUTH,
        json={
            "pdf": b64(blank_pdf()),
            "fields": [{"name": "a", "page": 0, "box": [0, 0, coordinate, 1]}],
        },
    )
    assert response.status_code == 422
