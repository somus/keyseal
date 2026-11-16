"""Configuration from the environment, checked once at startup."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .trust import ValidationSettings, trust_settings

DEFAULT_TSA_URL = "http://timestamp.digicert.com"
MIN_TOKEN_CHARS = 32
MIN_DISTINCT_CHARS = 10
DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class WeakTokenError(ValueError):
    pass


class LogLevelError(ValueError):
    pass


class TsaUrlError(ValueError):
    pass


def tsa_urls(value: str) -> tuple[str, ...]:
    """The timestamp authorities in `value`, URLs separated by commas or
    whitespace and tried in that order; none for an empty value or `none`."""
    urls = tuple(url for url in re.split(r"[\s,]+", value) if url)
    if urls in ((), ("none",)):
        return ()
    for url in urls:
        try:
            parts = urlsplit(url)
            valid = parts.scheme in ("http", "https") and bool(parts.hostname)
        except ValueError:
            valid = False
        if not valid:
            raise TsaUrlError(f"SIGNING_TSA_URL entry {url} is not an http or https URL")
    return urls


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


@dataclass(frozen=True)
class Settings:
    token: str
    #: Timestamp authorities, tried in order; none turns timestamping off.
    tsa_urls: tuple[str, ...]
    validation: ValidationSettings
    #: The level the service's own log records come out at.
    log_level: str = DEFAULT_LOG_LEVEL

    @classmethod
    def from_env(cls) -> Settings:
        log_level = os.environ.get("SIGNING_LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
        if log_level not in LOG_LEVELS:
            raise LogLevelError(
                f"SIGNING_LOG_LEVEL {os.environ['SIGNING_LOG_LEVEL']} is not one of"
                f" {', '.join(LOG_LEVELS)}"
            )
        roots_dir = os.environ.get("SIGNING_TRUST_ROOTS_DIR")
        extra_roots_dir = os.environ.get("SIGNING_EXTRA_TRUST_ROOTS_DIR")
        return cls(
            token=os.environ.get("SIGNING_SERVICE_TOKEN", ""),
            tsa_urls=tsa_urls(os.environ.get("SIGNING_TSA_URL", DEFAULT_TSA_URL)),
            validation=trust_settings(
                Path(roots_dir) if roots_dir else None,
                os.environ.get("SIGNING_ALLOW_FETCHING") == "true",
                Path(extra_roots_dir) if extra_roots_dir else None,
            ),
            log_level=log_level,
        )
