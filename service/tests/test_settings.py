from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from pyhanko_certvalidator import CertificateValidator

from keyseal_service.app import create_app
from keyseal_service.settings import TRUST, Settings, WeakTokenError, check_token
from keyseal_service.validate import (
    ValidationSettings,
    certificate_trusted,
    load_trust_roots,
)

from .conftest import TOKEN, Pki, _asn1


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
    settings = Settings(token="local-signing-token", tsa_urls=(), validation=ValidationSettings([]))
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
        create_app(settings)
    assert exited.value.code == 1
    assert "Refusing to start: SIGNING_SERVICE_TOKEN is shorter than 32 characters" in caplog.text


def test_bundled_cca_india_roots_load_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIGNING_TRUST_ROOTS_DIR", raising=False)
    settings = Settings.from_env()
    assert len(settings.validation.trust_roots) == 1
    assert len(settings.validation.intermediates) == 2
    assert settings.tsa_urls == ("http://timestamp.digicert.com",)


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
    assert settings.tsa_urls == ()


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


def test_an_extra_roots_dir_adds_to_the_bundled_roots(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SIGNING_TRUST_ROOTS_DIR", raising=False)
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("SIGNING_EXTRA_TRUST_ROOTS_DIR", str(tmp_path))
    pki.write_ca(tmp_path)
    settings = Settings.from_env()
    validation = settings.validation
    assert len(validation.trust_roots) == 2
    assert validation.trust_roots[-1].sha256 == pki.ca_asn1.sha256
    assert len(validation.intermediates) == 2
    with TestClient(create_app(settings)) as client:
        assert client.get("/health").json()["trustRoots"] == 2
    # A certificate from the extra root is trusted.
    signer = _asn1(pki.signer_cert)
    assert asyncio.run(certificate_trusted(signer, [pki.ca_asn1], validation))[0] is True
    # A CCA India chain still ends in the bundled root, checked at a fixed
    # time inside the sub CA's validity (2022-02-16 to 2032-02-16).
    sub_ca = load_trust_roots(TRUST / "intermediates")[-1]
    moment = datetime(2026, 6, 1, tzinfo=UTC)
    path = asyncio.run(
        CertificateValidator(
            sub_ca, validation_context=validation.context(moment=moment)
        ).async_validate_path()
    )
    assert path.trust_anchor.authority.name.native["common_name"] == "CCA India 2022"
    assert validation.is_configured_root(path)


def test_an_extra_roots_dir_adds_to_a_roots_dir(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base, extra = tmp_path / "base", tmp_path / "extra"
    base.mkdir()
    extra.mkdir()
    other = Pki()
    other.write_ca(base)
    pki.write_ca(extra)
    (extra / "signer.der").write_bytes(pki.signer_cert.public_bytes(serialization.Encoding.DER))
    monkeypatch.setenv("SIGNING_TRUST_ROOTS_DIR", str(base))
    monkeypatch.setenv("SIGNING_EXTRA_TRUST_ROOTS_DIR", str(extra))
    validation = Settings.from_env().validation
    assert [c.sha256 for c in validation.trust_roots] == [
        other.ca_asn1.sha256,
        pki.ca_asn1.sha256,
    ]
    assert [c.sha256 for c in validation.intermediates] == [_asn1(pki.signer_cert).sha256]


def test_an_extra_roots_dir_without_certificates_refuses_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("SIGNING_TRUST_ROOTS_DIR", raising=False)
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    unreadable = tmp_path / "unreadable"
    unreadable.mkdir()
    (unreadable / "root.pem").write_bytes(b"not a certificate")
    for directory in (tmp_path / "missing", tmp_path / "unreadable"):
        monkeypatch.setenv("SIGNING_EXTRA_TRUST_ROOTS_DIR", str(directory))
        with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
            create_app()
        assert exited.value.code == 1
        assert f"SIGNING_EXTRA_TRUST_ROOTS_DIR {directory} holds no readable certificate" in (
            caplog.text
        )
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("SIGNING_EXTRA_TRUST_ROOTS_DIR", str(empty))
    with pytest.raises(SystemExit):
        create_app()


def test_an_extra_roots_dir_that_cannot_be_listed_refuses_to_start(
    pki: Pki, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("SIGNING_TRUST_ROOTS_DIR", raising=False)
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("SIGNING_EXTRA_TRUST_ROOTS_DIR", str(tmp_path))
    pki.write_ca(tmp_path)
    tmp_path.chmod(0)
    try:
        with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
            create_app()
    finally:
        tmp_path.chmod(0o700)
    assert exited.value.code == 1
    assert f"SIGNING_EXTRA_TRUST_ROOTS_DIR {tmp_path} is unreadable" in caplog.text


@pytest.mark.parametrize(
    ("level", "shown"), [(None, True), ("DEBUG", True), ("warning", False)]
)
def test_service_records_come_out_at_the_configured_level(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, level: str | None, shown: bool
) -> None:
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    if level is None:
        monkeypatch.delenv("SIGNING_LOG_LEVEL", raising=False)
    else:
        monkeypatch.setenv("SIGNING_LOG_LEVEL", level)
    create_app()
    logging.getLogger("keyseal_service.validate").info("Certificate refused: a CA certificate")
    assert ("Certificate refused: a CA certificate" in caplog.text) is shown


def test_an_unknown_log_level_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("SIGNING_LOG_LEVEL", "verbose")
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
        create_app()
    assert exited.value.code == 1
    assert "Refusing to start: SIGNING_LOG_LEVEL verbose is not" in caplog.text


@pytest.mark.parametrize(
    ("value", "urls"),
    [
        ("", ()),
        ("none", ()),
        ("https://one.example/tsa", ("https://one.example/tsa",)),
        (
            "https://one.example/tsa, http://two.example\n  http://three.example",
            ("https://one.example/tsa", "http://two.example", "http://three.example"),
        ),
    ],
)
def test_the_tsa_list_is_split_on_commas_and_whitespace(
    monkeypatch: pytest.MonkeyPatch, value: str, urls: tuple[str, ...]
) -> None:
    monkeypatch.setenv("SIGNING_TSA_URL", value)
    assert Settings.from_env().tsa_urls == urls


@pytest.mark.parametrize(
    ("value", "entry"),
    [
        ("timestamp.digicert.com", "timestamp.digicert.com"),
        ("http://one.example, none", "none"),
        ("https://one.example ftp://two.example", "ftp://two.example"),
        ("http://[::1", "http://[::1"),
    ],
)
def test_a_tsa_list_with_anything_but_http_urls_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, value: str, entry: str
) -> None:
    monkeypatch.setenv("SIGNING_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("SIGNING_TSA_URL", value)
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exited:
        create_app()
    assert exited.value.code == 1
    assert (
        f"Refusing to start: SIGNING_TSA_URL entry {entry} is not an http or https URL"
        in caplog.text
    )
