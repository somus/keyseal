"""HTTP API. Every request but GET /health carries the shared bearer token.

Run with `uvicorn keyseal_service.app:create_app --factory`. Stamp styles and
extra routers come from installed packages through entry points:
`keyseal.stamp_styles` maps a name to a callable returning a pyHanko stamp
style, and `keyseal.routers` maps a name to a callable taking the `Settings`
and returning an `APIRouter`, mounted behind the bearer token. `RequestGuard`
checks the token and caps the body before any route, plugin ones included,
reads it.
"""

from __future__ import annotations

import base64
import binascii
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from importlib.metadata import entry_points
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, StringConstraints
from pyhanko.sign import timestamps
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend

from . import remote_sign
from .appearance import SignedByStampStyle
from .fetching import public_fetch_session
from .prepare import MAX_FIELDS, FieldRequest, PrepareError, prepare_fields
from .request_guard import RequestGuard
from .settings import Settings, TrustRootsError, WeakTokenError, check_token
from .validate import certificate_trusted, validate_pdf_async

log = logging.getLogger(__name__)

MAX_PDF_BYTES = 25 * 1024 * 1024
#: Base64 of a PDF of MAX_PDF_BYTES.
MAX_PDF_CHARS = -(-MAX_PDF_BYTES // 3) * 4
MAX_STATE_CHARS = 60 * 1024 * 1024
#: A JSON body is read whole before it is parsed, so the guard caps every
#: body but a raw PDF's at the largest request, /sign/finish.
MAX_BODY_BYTES = MAX_STATE_CHARS + 16 * 1024
#: Routes whose body is a raw PDF, capped at MAX_PDF_BYTES instead.
PDF_PATHS = frozenset({"/validate", "/finalize", "/retimestamp"})
MAX_CERTIFICATE_CHARS = 16 * 1024
MAX_SIGNATURE_CHARS = 4096
MAX_DETAIL_CHARS = 200
DEFAULT_STAMP_STYLE = "signed-by"
STAMP_STYLES_GROUP = "keyseal.stamp_styles"
ROUTERS_GROUP = "keyseal.routers"


#: A page coordinate: finite and within the largest page PDF allows.
Coordinate = Annotated[float, Field(allow_inf_nan=False, ge=-14400, le=14400)]
Pdf = Annotated[str, Field(max_length=MAX_PDF_CHARS, description="A PDF, base64")]
Certificate = Annotated[
    str, Field(max_length=MAX_CERTIFICATE_CHARS, description="A certificate, DER in base64")
]
Chain = Annotated[list[Certificate], Field(default_factory=list, max_length=8)]
#: Plain text for the signature dictionary: trimmed, without control characters.
DetailText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=MAX_DETAIL_CHARS,
        pattern=r"^[^\x00-\x1f\x7f-\x9f]*$",
    ),
]


class PrepareField(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_]+$")
    page: int
    box: tuple[Coordinate, Coordinate, Coordinate, Coordinate]


class SignStartRequest(BaseModel):
    pdf: Pdf
    fieldName: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_]+$")
    certificate: Certificate
    chain: Chain
    stampStyle: str = DEFAULT_STAMP_STYLE
    rsaPadding: Literal["pkcs1", "pss"] = "pkcs1"
    reason: DetailText | None = None
    location: DetailText | None = None
    contactInfo: DetailText | None = None


class CertificateRequest(BaseModel):
    certificate: Certificate
    chain: Chain


class SignFinishRequest(BaseModel):
    state: str = Field(max_length=MAX_STATE_CHARS)
    signature: str = Field(
        max_length=MAX_SIGNATURE_CHARS, description="The token's signature value, base64"
    )


class PrepareRequest(BaseModel):
    pdf: Pdf
    fields: list[PrepareField] = Field(max_length=MAX_FIELDS)


def create_app(settings: Settings | None = None) -> FastAPI:
    try:
        resolved = settings or Settings.from_env()
        check_token(resolved.token)
    except WeakTokenError as error:
        log.critical("Refusing to start: %s. Generate one with `openssl rand -base64 32`.", error)
        raise SystemExit(1) from error
    except TrustRootsError as error:
        log.critical("Refusing to start: %s.", error)
        raise SystemExit(1) from error

    validation = resolved.validation

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Routes see the shared public-only fetcher while the app runs; the
        # settings without it refuse to build a fetching context.
        nonlocal validation
        if not validation.allow_fetching:
            yield
            return
        async with public_fetch_session() as session:
            validation = replace(
                resolved.validation, fetcher_backend=AIOHttpFetcherBackend(session=session)
            )
            try:
                yield
            finally:
                validation = resolved.validation

    app = FastAPI(
        title="KeySeal signing service", docs_url=None, redoc_url=None, lifespan=lifespan
    )
    app.add_middleware(
        RequestGuard,
        token=resolved.token,
        max_body_bytes=MAX_BODY_BYTES,
        max_pdf_bytes=MAX_PDF_BYTES,
        pdf_paths=PDF_PATHS,
    )
    tsa = timestamps.HTTPTimeStamper(resolved.tsa_url) if resolved.tsa_url else None
    stamp_styles = {
        DEFAULT_STAMP_STYLE: SignedByStampStyle,
        **{ep.name: ep.load() for ep in entry_points(group=STAMP_STYLES_GROUP)},
    }
    state_key = remote_sign.state_key(resolved.token)

    def _b64(value: str, what: str) -> bytes:
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise HTTPException(400, f"{what} is not base64") from error

    def _pdf_b64(value: str) -> bytes:
        pdf = _b64(value, "pdf")
        if len(pdf) > MAX_PDF_BYTES:
            raise HTTPException(413, "PDF too large")
        return pdf

    async def _read_pdf(request: Request) -> bytes:
        # The guard caps the stream at MAX_PDF_BYTES.
        body = await request.body()
        if not body:
            raise HTTPException(400, "Empty body")
        return body

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"ok": True, "trustRoots": len(validation.trust_roots)}

    @app.post("/validate")
    async def validate(
        request: Request,
        base: int | None = Query(
            default=None, ge=1, description="Bytes of the copy the signer was given"
        ),
    ) -> dict[str, object]:
        return await validate_pdf_async(await _read_pdf(request), validation, base)

    @app.post("/certificate")
    async def certificate(body: CertificateRequest) -> dict[str, bool]:
        try:
            cert = remote_sign.load_cert(body.certificate)
            chain = [remote_sign.load_cert(c) for c in body.chain]
            remote_sign.algorithms(cert)
        except remote_sign.RemoteSignError as error:
            raise HTTPException(400, str(error)) from error
        trusted, revocation_checked = await certificate_trusted(cert, chain, validation)
        return {"revocationChecked": revocation_checked, "trusted": trusted}

    @app.post("/sign/start")
    async def sign_start(body: SignStartRequest) -> dict[str, str]:
        pdf = _pdf_b64(body.pdf)
        stamp_style = stamp_styles.get(body.stampStyle)
        if stamp_style is None:
            raise HTTPException(400, f"Unknown stamp style {body.stampStyle}")
        try:
            result = await remote_sign.start(
                pdf,
                body.fieldName,
                body.certificate,
                body.chain,
                stamp_style(),
                body.rsaPadding,
                remote_sign.SignatureDetails(
                    reason=body.reason, location=body.location, contact_info=body.contactInfo
                ),
            )
        except remote_sign.UnsupportedKeyError as error:
            raise HTTPException(400, str(error)) from error
        except remote_sign.RemoteSignError as error:
            raise HTTPException(422, str(error)) from error
        return {
            "digestAlgorithm": result.digest_algorithm,
            "signatureAlgorithm": result.signature_algorithm,
            "state": remote_sign.seal_state(state_key, result.state),
            "toSign": base64.b64encode(result.to_sign).decode(),
        }

    @app.post("/sign/finish")
    async def sign_finish(body: SignFinishRequest) -> Response:
        try:
            state = remote_sign.open_state(state_key, body.state)
            pdf = await remote_sign.finish(state, _b64(body.signature, "signature"), tsa)
        except remote_sign.RemoteSignError as error:
            raise HTTPException(422, str(error)) from error
        return Response(content=pdf, media_type="application/pdf")

    @app.post("/finalize")
    async def finalize(request: Request) -> Response:
        if tsa is None:
            raise HTTPException(503, "No timestamp authority is configured")
        pdf = await _read_pdf(request)
        try:
            out = await remote_sign.finalize(pdf, tsa, validation.context())
        except Exception as error:  # noqa: BLE001 - reported, the PDF stays as it was
            log.exception("Couldn't finalise")
            raise HTTPException(422, f"Couldn't finalise: {type(error).__name__}") from error
        return Response(content=out, media_type="application/pdf")

    @app.post("/retimestamp")
    async def retimestamp(request: Request) -> Response:
        if tsa is None:
            raise HTTPException(503, "No timestamp authority is configured")
        pdf = await _read_pdf(request)
        try:
            out = await remote_sign.retimestamp(pdf, tsa, validation.context())
        except Exception as error:  # noqa: BLE001 - reported, the PDF stays as it was
            log.exception("Couldn't timestamp")
            raise HTTPException(422, f"Couldn't timestamp: {type(error).__name__}") from error
        return Response(content=out, media_type="application/pdf")

    @app.post("/prepare")
    def prepare(body: PrepareRequest) -> Response:
        pdf = _pdf_b64(body.pdf)
        try:
            prepared = prepare_fields(
                pdf,
                [
                    FieldRequest(
                        name=f.name,
                        page=f.page,
                        box=tuple(int(round(v)) for v in f.box),  # type: ignore[arg-type]
                    )
                    for f in body.fields
                ],
            )
        except PrepareError as error:
            raise HTTPException(422, str(error)) from error
        return Response(content=prepared, media_type="application/pdf")

    for ep in entry_points(group=ROUTERS_GROUP):
        app.include_router(ep.load()(resolved))

    return app
