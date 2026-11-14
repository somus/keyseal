"""GET /ready: whether a timestamp authority answered lately."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import pytest
from pyhanko.sign import timestamps

from keyseal_service import app as app_module, timestamping
from keyseal_service.timestamping import TimestampAuthorities
from keyseal_service.validate import ValidationSettings

from .conftest import Pki, client_for
from .test_timestamping import DIGEST, Down, Silent


class Counting(timestamps.TimeStamper):
    """A local TSA that counts its requests and answers after `delay`."""

    def __init__(self, pki: Pki, delay: float = 0) -> None:
        super().__init__()
        self.tsa = pki.timestamper(datetime.now(UTC))
        self.delay = delay
        self.requests = 0

    async def async_timestamp(self, message_digest: bytes, md_algorithm: str) -> Any:
        self.requests += 1
        await asyncio.sleep(self.delay)
        return await self.tsa.async_timestamp(message_digest, md_algorithm)


def _client(monkeypatch: pytest.MonkeyPatch, *stampers: timestamps.TimeStamper) -> Any:
    by_url = {f"https://tsa{i}.example/secret-path": s for i, s in enumerate(stampers)}
    monkeypatch.setattr(app_module.timestamps, "HTTPTimeStamper", lambda url, **_: by_url[url])
    return client_for(ValidationSettings([]), tuple(by_url))


def test_ready_needs_no_token_and_is_ready_with_timestamps_off() -> None:
    response = client_for(ValidationSettings([])).get("/ready")
    assert response.status_code == 200
    assert response.json() == {"ready": True, "checks": {"tsa": "off"}}


def test_an_answering_authority_is_ready_and_checked_once_a_minute(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(timestamping.time, "monotonic", lambda: clock[0])
    tsa = Counting(pki)
    client = _client(monkeypatch, tsa)
    for _ in range(3):
        response = client.get("/ready")
        assert response.status_code == 200
        assert response.json() == {"ready": True, "checks": {"tsa": "ok"}}
    assert tsa.requests == 1
    clock[0] += timestamping.READY_FRESH_SECONDS
    assert client.get("/ready").status_code == 200
    assert tsa.requests == 2


def test_no_authority_answering_is_503_naming_none_of_them(
    pki: Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    down = Down()
    client = _client(monkeypatch, down, Down(OSError()))
    with caplog.at_level(logging.ERROR):
        responses = [client.get("/ready") for _ in range(2)]
    for response in responses:
        assert response.status_code == 503
        assert response.json() == {"ready": False, "checks": {"tsa": "unreachable"}}
        assert "example" not in response.text
    assert down.requests == 1
    assert "Every timestamp authority failed: tsa0.example" in caplog.text


def test_the_fallback_answers_for_a_dead_first_authority(
    pki: Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = _client(monkeypatch, Down(), Counting(pki)).get("/ready")
    assert response.json() == {"ready": True, "checks": {"tsa": "ok"}}


def test_a_timestamp_for_a_request_counts_without_a_check(pki: Pki) -> None:
    tsa = Counting(pki)
    authorities = TimestampAuthorities([("https://tsa.example", tsa)])

    async def stamp_then_probe() -> bool:
        await authorities.stamper().async_timestamp(DIGEST, "sha256")
        return await authorities.ready()

    assert asyncio.run(stamp_then_probe()) is True
    assert tsa.requests == 1


def test_a_failed_request_counts_as_unreachable_without_a_check() -> None:
    down = Down()
    authorities = TimestampAuthorities([("https://tsa.example", down)])

    async def stamp_then_probe() -> bool:
        with pytest.raises(timestamping.TimestampUnavailableError):
            await authorities.stamper().async_timestamp(DIGEST, "sha256")
        return await authorities.ready()

    assert asyncio.run(stamp_then_probe()) is False
    assert down.requests == 1


def test_concurrent_probes_share_one_check(pki: Pki) -> None:
    tsa = Counting(pki, delay=0.05)
    authorities = TimestampAuthorities([("https://tsa.example", tsa)])

    async def probes() -> list[bool]:
        return await asyncio.gather(*(authorities.ready() for _ in range(5)))

    assert asyncio.run(probes()) == [True] * 5
    assert tsa.requests == 1


def test_a_probe_waits_only_so_long(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(timestamping, "READY_WAIT_SECONDS", 0.05)
    authorities = TimestampAuthorities([("https://tsa.example", Silent())])

    async def probe() -> tuple[bool, float]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        ready = await authorities.ready()
        return ready, loop.time() - started

    ready, took = asyncio.run(probe())
    assert ready is False
    assert took < 1
