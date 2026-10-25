# KeySeal signing service

A pyHanko service behind FastAPI. It prepares PDFs with empty signature fields, returns the DER SignedAttributes a token signs, embeds the returned signature with a timestamp, validates signed PDFs and adds long-term validation data. The signer's key never reaches it; only the integrator backend talks to it, over a private network.

Every route except `GET /health` needs `Authorization: Bearer $SIGNING_SERVICE_TOKEN`.

| Route | Does |
|---|---|
| `GET /health` | Liveness and the number of trust roots loaded |
| `POST /validate?base=<bytes>` | Validation report for a PDF body; `base` adds what changed since the copy the signer was given |
| `POST /certificate` | Whether a certificate chains to a configured root and may sign |
| `POST /prepare` | Adds empty signature fields as one incremental update |
| `POST /sign/start` | Reserves the signature and returns `toSign`, `digestAlgorithm` (`sha256` or `sha384`), `signatureAlgorithm` (`rsa-pkcs1-v1_5`, `rsa-pss` or `ecdsa`) and an opaque `state`; optional `stampStyle`, `rsaPadding` (`pkcs1` or `pss`), `reason`, `location` and `contactInfo` |
| `POST /sign/finish` | Builds the CMS around the token's signature and returns the signed PDF (PAdES B-T) |
| `POST /finalize` | Revocation data for every signature and a document timestamp (PAdES B-LTA) |
| `POST /retimestamp` | Another document timestamp before the last one's certificate expires |

`reason`, `location` and `contactInfo` go into the signature dictionary as `/Reason`, `/Location` and `/ContactInfo`, which PDF viewers show in their signature panel. Each is trimmed and must then be 1 to 200 characters without control characters, or the request is a 422. They are written into the prepared PDF at `/sign/start`, so the state's MAC covers them and `/sign/finish` takes nothing more. The built-in stamp adds a `Reason:` line, wrapped to two lines and shortened past that.

The `state` from `/sign/start` is a JSON object passed back unchanged to `/sign/finish`. Its `output` member, base64 of the prepared PDF that `toSign` was computed for, is a stable part of this API: `@keyseal/server` reads it to serve the document to the helper. Every other member is opaque and may change.

The state's last member, `mac`, is an HMAC-SHA256 over the exact JSON text before it, keyed with HMAC-SHA256 of the label `keyseal-service sign state v1` under the bearer token. `/sign/finish` refuses a state whose MAC is missing or doesn't match with a 422 before reading anything in it, so no member can change, and a state from before the token was rotated is refused too.

Supported keys: RSA (PKCS#1 v1.5 or PSS with MGF1 and a 32-byte salt, SHA-256) and ECDSA P-256 (SHA-256) or P-384 (SHA-384), with ECDSA signatures as DER `ECDSA-Sig-Value`. PDFs are limited to 25 MB.

## Run

```bash
cd service
uv sync
uv run pytest
SIGNING_SERVICE_TOKEN="$(openssl rand -base64 32)" \
  uv run uvicorn keyseal_service.app:create_app --factory --port 8090
```

The service refuses to start, logging which rule failed and exiting 1, when the token is unset, shorter than 32 characters, or has fewer than 10 distinct characters. Both `openssl rand -base64 32` and `openssl rand -hex 32` pass.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `SIGNING_SERVICE_TOKEN` | none, required | Bearer token shared with the integrator backend |
| `SIGNING_TSA_URL` | `http://timestamp.digicert.com` | RFC 3161 timestamp authority; `none` turns timestamps off, and `/finalize` and `/retimestamp` then answer 503 |
| `SIGNING_TRUST_ROOTS_DIR` | bundled CCA India roots and intermediates | Directory of `.pem`, `.cer`, `.crt` or `.der` certificates replacing the bundled ones; self-signed ones are roots, the rest intermediates |
| `SIGNING_ALLOW_FETCHING` | off | `true` lets validation fetch OCSP and CRL data |
| `TZ` | container's (UTC) | Time zone of the date in the built-in stamp, for example `Asia/Kolkata`; a zone name, since pyHanko refuses POSIX zones such as `IST-5:30` |

Setting `SIGNING_TRUST_ROOTS_DIR` replaces both the bundled CCA India roots and the bundled intermediates, so put every root and intermediate the chains need in that directory. The service refuses to start when the directory holds no readable root.

## Plugins

Install a package into the image that declares entry points. A stamp style is a callable returning a pyHanko stamp style, chosen with `"stampStyle": "<name>"` on `/sign/start` (the built-in one is `signed-by`; an unknown name is a 400). The style's text parameters are `signer`, `reason`, `location` and `contact_info`, the last three empty when not given, so a `TextStampStyle` can show them with `%(reason)s`. A router factory takes the service's `Settings` and returns an `APIRouter`, mounted behind the bearer token.

```toml
# pyproject.toml of your plugin
[project.entry-points."keyseal.stamp_styles"]
acme = "acme_keyseal:stamp_style"

[project.entry-points."keyseal.routers"]
acme = "acme_keyseal:router"
```

```python
# acme_keyseal/__init__.py
from fastapi import APIRouter
from pyhanko.stamp import TextStampStyle

def stamp_style():
    return TextStampStyle(stamp_text="Signed for Acme by %(signer)s")

def router(settings):
    r = APIRouter(prefix="/acme")
    r.get("/ping")(lambda: {"trustRoots": len(settings.validation.trust_roots)})
    return r
```

## Docker

```bash
docker build -t keyseal-service service
docker run --rm -p 8080:8080 \
  -e SIGNING_SERVICE_TOKEN="$(openssl rand -base64 32)" \
  keyseal-service
```

A derived image adds plugins and, if needed, its own roots:

```dockerfile
FROM keyseal-service
USER root
RUN uv pip install --python /app/.venv/bin/python acme-keyseal
USER signing
```

The bundled Geist font is under the SIL Open Font License; see `keyseal_service/fonts/OFL-Geist.txt`.
