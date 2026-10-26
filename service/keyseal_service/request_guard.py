"""Checks the bearer token before any route reads a body, then caps the body
as it streams in, so a chunked upload can't run past the limit either."""

from __future__ import annotations

import hmac
from collections.abc import Collection

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocketClose


class RequestGuard:
    def __init__(
        self,
        app: ASGIApp,
        token: str,
        max_body_bytes: int,
        max_pdf_bytes: int,
        pdf_paths: Collection[str],
    ) -> None:
        self.app = app
        self.expected = token.encode()
        self.max_body_bytes = max_body_bytes
        self.max_pdf_bytes = max_pdf_bytes
        self.pdf_paths = pdf_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan" or (
            scope["type"] == "http" and scope["method"] == "GET" and scope["path"] == "/health"
        ):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        scheme, _, supplied = headers.get("authorization", "").partition(" ")
        if scheme != "Bearer" or not hmac.compare_digest(supplied.strip().encode(), self.expected):
            if scope["type"] == "websocket":
                await WebSocketClose(code=1008)(scope, receive, send)
            else:
                await JSONResponse({"detail": "Unauthorized"}, status_code=401)(
                    scope, receive, send
                )
            return
        if scope["type"] == "websocket":
            # A plugin's websocket route: authenticated, and its messages aren't a body.
            await self.app(scope, receive, send)
            return

        limit = self.max_pdf_bytes if scope["path"] in self.pdf_paths else self.max_body_bytes
        declared = headers.get("content-length")
        if declared is not None:
            if not (declared.isascii() and declared.isdigit()):
                await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(
                    scope, receive, send
                )
                return
            if int(declared) > limit:
                await JSONResponse({"detail": "Body too large"}, status_code=413)(
                    scope, receive, send
                )
                return

        size = 0

        async def bounded_receive() -> Message:
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > limit:
                    # Raised inside the route, so FastAPI answers it like its own.
                    raise HTTPException(413, "Body too large")
            return message

        await self.app(scope, bounded_receive, send)
