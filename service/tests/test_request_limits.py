"""The token and body limits at the ASGI boundary, driven by hand so no client
buffers the body first and every read is counted."""

from __future__ import annotations

import asyncio
from importlib.metadata import EntryPoint
from typing import Any

import pytest
from fastapi import APIRouter, Request, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from keyseal_service import app as app_module
from keyseal_service.settings import Settings
from keyseal_service.validate import ValidationSettings

from .conftest import AUTH, TOKEN

JSON_PATHS = ["/certificate", "/prepare", "/sign/start", "/sign/finish", "/extra/echo"]
PDF_PATHS = ["/validate", "/finalize", "/retimestamp"]
PATHS = JSON_PATHS + PDF_PATHS


def echo_router(_: Settings) -> APIRouter:
    router = APIRouter()

    @router.post("/extra/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"bytes": len(await request.body())}

    @router.websocket("/extra/socket")
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("open")
        await websocket.close()

    return router


@pytest.fixture(autouse=True)
def plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    group = app_module.ROUTERS_GROUP
    registered = {group: [EntryPoint("echo", f"{__name__}:echo_router", group)]}
    monkeypatch.setattr(app_module, "entry_points", lambda group: registered.get(group, []))


def request(
    path: str,
    chunks: list[bytes],
    *,
    authorization: bytes | None = f"Bearer {TOKEN}".encode(),
    content_length: str | None = None,
) -> tuple[int, list[int]]:
    """The response status and the indexes of the body chunks the app read."""
    reads: list[int] = []
    messages: list[dict[str, Any]] = []
    headers = [(b"content-type", b"application/json")]
    if authorization is not None:
        headers.append((b"authorization", authorization))
    if content_length is not None:
        headers.append((b"content-length", content_length.encode()))

    async def receive() -> dict[str, Any]:
        index = len(reads)
        reads.append(index)
        assert index < len(chunks), "The service read past the refused body"
        return {"type": "http.request", "body": chunks[index], "more_body": index < len(chunks) - 1}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    app = app_module.create_app(
        Settings(token=TOKEN, tsa_url="https://tsa.example", validation=ValidationSettings([]))
    )
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET" if path == "/health" else "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1),
    }
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    return status, reads


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize(
    "authorization", [None, b"Bearer wrong", TOKEN.encode(), f"bearer {TOKEN}".encode()]
)
def test_an_unauthenticated_body_is_never_read(path: str, authorization: bytes | None) -> None:
    assert request(path, [], authorization=authorization) == (401, [])


def test_health_needs_no_token() -> None:
    assert request("/health", [], authorization=None) == (200, [])


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("declared", [None, "1", "33"])
def test_streamed_and_declared_oversized_bodies_are_413(
    path: str, declared: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "MAX_BODY_BYTES", 32)
    monkeypatch.setattr(app_module, "MAX_PDF_BYTES", 32)
    status, reads = request(path, [b" " * 16, b" " * 17, b"unread"], content_length=declared)
    assert status == 413
    # A declared length over the limit is refused unread; otherwise the
    # stream is cut at the chunk that crosses it.
    assert reads == ([] if declared == "33" else [0, 1])


@pytest.mark.parametrize("path", ["/certificate", "/validate"])
@pytest.mark.parametrize("declared", ["-1", "abc", "1_0", "+5", " 5", ""])
def test_an_invalid_content_length_is_400(path: str, declared: str) -> None:
    assert request(path, [b"{}"], content_length=declared) == (400, [])


def test_each_route_has_its_own_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_module, "MAX_BODY_BYTES", 64)
    monkeypatch.setattr(app_module, "MAX_PDF_BYTES", 16)
    assert request("/extra/echo", [b" " * 40])[0] == 200
    assert request("/validate", [b" " * 40])[0] == 413


def test_authenticated_json_reaches_the_route() -> None:
    assert request("/certificate", [b'{"certificate":"invalid"}']) == (400, [0])


def test_the_pdf_limit_is_25_mb() -> None:
    assert app_module.MAX_PDF_BYTES == 25 * 1024 * 1024
    assert request("/validate", [b"%PDF"], content_length=str(25 * 1024 * 1024 + 1)) == (413, [])


def test_a_plugin_websocket_needs_the_token() -> None:
    app = app_module.create_app(
        Settings(token=TOKEN, tsa_url=None, validation=ValidationSettings([]))
    )
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect("/extra/socket"):
            pass
    assert refused.value.code == 1008
    with client.websocket_connect("/extra/socket", headers=AUTH) as websocket:
        assert websocket.receive_text() == "open"
