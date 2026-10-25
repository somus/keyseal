from __future__ import annotations

import logging
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from keyseal_service.app import create_app
from keyseal_service.settings import Settings, WeakTokenError, check_token
from keyseal_service.validate import ValidationSettings

from .conftest import TOKEN, Pki


@pytest.mark.parametrize(
    ("token", "reason"),
    [
        ("", "not set"),
        ("changeme", "shorter than 32"),
        ("Ab1-" * 7, "shorter than 32"),
        ("a" * 32, "fewer than 10 distinct"),
        ("ab" * 16, "fewer than 10 distinct"),
        ("abcdefghi" * 4, "fewer than 10 distinct"),
    ],
)
def test_weak_tokens_are_refused(token: str, reason: str) -> None:
    with pytest.raises(WeakTokenError, match=reason):
        check_token(token)


def test_a_strong_token_passes() -> None:
    check_token(TOKEN)


def test_openssl_tokens_pass() -> None:
    check_token("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")  # rand -hex 32
    check_token("q3Xv8kZJ0m+R2tW9yLp4NcB7hF1sD6eA5gU0iO3jKxE=")  # rand -base64 32


def test_a_hex_token_missing_one_digit_passes() -> None:
    check_token("0123456789abcde" * 4 + "0123")  # 15 distinct, no f


def test_the_service_refuses_to_start_with_a_weak_token(
    caplog: pytest.LogCaptureFixture,
) -> None:
    settings = Settings(token="local-signing-token", tsa_url=None, validation=ValidationSettings([]))
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
        create_app(settings)
    assert exited.value.code == 1
    assert "Refusing to start: SIGNING_SERVICE_TOKEN is shorter than 32 characters" in caplog.text


def test_bundled_cca_india_roots_load_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIGNING_TRUST_ROOTS_DIR", raising=False)
    settings = Settings.from_env()
    assert len(settings.validation.trust_roots) == 1
    assert len(settings.validation.intermediates) == 2
    assert settings.tsa_url == "http://timestamp.digicert.com"


def test_a_roots_dir_replaces_the_bundled_roots(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pki.write_ca(tmp_path)
    (tmp_path / "signer.der").write_bytes(pki.signer_cert.public_bytes(serialization.Encoding.DER))
    monkeypatch.setenv("SIGNING_TRUST_ROOTS_DIR", str(tmp_path))
    monkeypatch.setenv("SIGNING_TSA_URL", "none")
    settings = Settings.from_env()
    assert [c.sha256 for c in settings.validation.trust_roots] == [pki.ca_asn1.sha256]
    assert [c.subject.native["common_name"] for c in settings.validation.intermediates] == [
        "PRIYA S RAGHAVAN"
    ]
    assert settings.tsa_url is None


def test_a_roots_dir_without_roots_refuses_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    for directory in (tmp_path / "missing", tmp_path):
        monkeypatch.setenv("SIGNING_TRUST_ROOTS_DIR", str(directory))
        with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
            create_app()
        assert exited.value.code == 1
        assert "holds no readable root" in caplog.text
