"""HTTP(S) transport for certificate issuer, OCSP and CRL URLs.

Those URLs come from the certificates being checked, so anyone who can send
one picks them. Every request goes straight to a public address: no proxy,
no environment settings, no cookies, and each redirect is checked again.
Response bodies are capped too, so a responder can't fill the memory.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from ipaddress import IPv6Address, ip_address
from typing import Any

import aiohttp
import certifi
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import DefaultResolver

#: A CRL grows by a few dozen bytes per revoked certificate still unexpired,
#: so this leaves room for a busy CA's while bounding memory and parse time.
#: Issuer certificates come over GET too and are far smaller.
MAX_CRL_BYTES = 8 * 1024 * 1024
#: An OCSP response covers one certificate and is a few KB even with the
#: responder's own certificate chain embedded.
MAX_OCSP_RESPONSE_BYTES = 64 * 1024


class ResponseTooLarge(aiohttp.ClientPayloadError):
    pass


class BoundedResponse(aiohttp.ClientResponse):
    """Reads at most the cap for its request: OCSP is the only POST. The
    count is of the decoded body, so a compressed one can't expand past it.
    pyHanko's fetchers take this, like any other client error, as a failed
    fetch, so the revocation data counts as unavailable."""

    async def read(self) -> bytes:
        if self._body is None:
            limit = MAX_OCSP_RESPONSE_BYTES if self.method == "POST" else MAX_CRL_BYTES
            too_large = ResponseTooLarge(f"Certificate fetch response over {limit} bytes")
            if (self.content_length or 0) > limit:
                self.close()
                raise too_large
            body = bytearray()
            while chunk := await self.content.read(limit + 1 - len(body)):
                body += chunk
                if len(body) > limit:
                    self.close()
                    raise too_large
            self._body = bytes(body)
        return await super().read()


def _require_public(address: str) -> None:
    try:
        ip = ip_address(address)
    except ValueError as error:
        raise OSError("Certificate fetch destination must be a numeric public IP") from error
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if "%" in address or not ip.is_global or ip.is_multicast or ip.is_reserved:
        raise OSError("Certificate fetch destination must be a public IP")


class PublicResolver(AbstractResolver):
    """Refuses a name when any of its addresses isn't public."""

    def __init__(self) -> None:
        self._resolver = DefaultResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
    ) -> list[ResolveResult]:
        answers = await self._resolver.resolve(host, port, family)
        for answer in answers:
            _require_public(answer["host"])
        return answers

    async def close(self) -> None:
        await self._resolver.close()


def public_socket(addr_info: tuple[Any, ...]) -> socket.socket:
    # aiohttp connects this socket to the same numeric address, so no second
    # lookup can swap the checked answer, and IP literals are checked here too.
    family, kind, protocol, _, address = addr_info
    _require_public(address[0])
    return socket.socket(family=family, type=kind, proto=protocol)


async def _direct_http_only(
    request: aiohttp.ClientRequest,
    handler: Callable[[aiohttp.ClientRequest], Awaitable[aiohttp.ClientResponse]],
) -> aiohttp.ClientResponse:
    # Client middleware runs again for each redirect, before a connection is reused.
    if request.url.scheme not in {"http", "https"} or request.proxy is not None:
        raise aiohttp.ClientConnectionError("Certificate fetching requires direct HTTP(S)")
    return await handler(request)


@asynccontextmanager
async def public_fetch_session() -> AsyncIterator[aiohttp.ClientSession]:
    resolver = PublicResolver()
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                resolver=resolver,
                use_dns_cache=False,
                socket_factory=public_socket,
                ssl=ssl.create_default_context(cafile=certifi.where()),
            ),
            middlewares=(_direct_http_only,),
            response_class=BoundedResponse,
            trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            yield session
    finally:
        await resolver.close()
