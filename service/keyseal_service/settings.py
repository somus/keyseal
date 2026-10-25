"""Configuration from the environment, checked once at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .validate import ValidationSettings, load_trust_roots, split_trust_roots

TRUST = Path(__file__).resolve().parent / "trust"
DEFAULT_TSA_URL = "http://timestamp.digicert.com"
MIN_TOKEN_CHARS = 32
MIN_DISTINCT_CHARS = 10


class WeakTokenError(ValueError):
    pass


class TrustRootsError(ValueError):
    pass


def check_token(token: str) -> None:
    """Refuses an unset, short or low-variety bearer token."""
    if not token:
        raise WeakTokenError("SIGNING_SERVICE_TOKEN is not set")
    if len(token) < MIN_TOKEN_CHARS:
        raise WeakTokenError(f"SIGNING_SERVICE_TOKEN is shorter than {MIN_TOKEN_CHARS} characters")
    if len(set(token)) < MIN_DISTINCT_CHARS:
        raise WeakTokenError(
            f"SIGNING_SERVICE_TOKEN has fewer than {MIN_DISTINCT_CHARS} distinct characters"
        )


def trust_settings(roots_dir: Path | None, allow_fetching: bool) -> ValidationSettings:
    """The bundled CCA India roots and intermediates, or every certificate in
    `roots_dir`, where self-signed ones are roots and the rest intermediates."""
    if roots_dir is None:
        roots = load_trust_roots(TRUST / "roots")
        intermediates = load_trust_roots(TRUST / "intermediates")
    else:
        roots, intermediates = split_trust_roots(load_trust_roots(roots_dir))
        # A mistyped directory would otherwise start a service that trusts
        # nobody and reports every signature as untrusted.
        if not roots:
            raise TrustRootsError(f"SIGNING_TRUST_ROOTS_DIR {roots_dir} holds no readable root")
    return ValidationSettings(
        trust_roots=roots, intermediates=intermediates, allow_fetching=allow_fetching
    )


@dataclass(frozen=True)
class Settings:
    token: str
    #: None turns timestamping off.
    tsa_url: str | None
    validation: ValidationSettings

    @classmethod
    def from_env(cls) -> Settings:
        roots_dir = os.environ.get("SIGNING_TRUST_ROOTS_DIR")
        tsa_url = os.environ.get("SIGNING_TSA_URL", DEFAULT_TSA_URL)
        return cls(
            token=os.environ.get("SIGNING_SERVICE_TOKEN", ""),
            tsa_url=None if tsa_url in ("", "none") else tsa_url,
            validation=trust_settings(
                Path(roots_dir) if roots_dir else None,
                os.environ.get("SIGNING_ALLOW_FETCHING") == "true",
            ),
        )
