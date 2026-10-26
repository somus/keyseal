"""HTTP(S) transport for certificate issuer, OCSP and CRL URLs.

Those URLs come from the certificates being checked, so anyone who can send
one picks them. Every request goes straight to a public address: no proxy,
no environment settings, no cookies, and each redirect is checked again.
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
            trust_env=False,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            yield session
    finally:
        await resolver.close()
