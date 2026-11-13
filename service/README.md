# KeySeal signing service

A pyHanko service behind FastAPI. It prepares PDFs with empty signature fields, returns the DER SignedAttributes a token signs, embeds the returned signature with a timestamp, validates signed PDFs and adds long-term validation data. The signer's key never reaches it; only the integrator backend talks to it, over a private network.

Every route except `GET /health`, plugin routes included, needs `Authorization: Bearer $SIGNING_SERVICE_TOKEN`. The token is checked before any of the body is read, and a missing or wrong one is a 401.

| Route | Does |
|---|---|
| `GET /health` | Liveness and the number of trust roots loaded |
| `POST /validate?base=<bytes>&keyUsage=<usage>` | Validation report for a PDF body; `base` adds what changed since the copy the signer was given, and `keyUsage` is the key usage a `trusted` signer's certificate asserts (below). Each signature's `timestampValid` is whether its signature timestamp is intact and matches the signature, `null` without one; a signature with an invalid timestamp makes the report `invalid` |
| `POST /certificate` | Whether a certificate chains to a configured root and may sign (`trusted`), and whether its revocation status was checked (`revocationChecked`); optional `keyUsage` (below) |
| `POST /prepare` | Adds empty signature fields as one incremental update |
| `POST /sign/start` | Reserves the signature and returns `toSign`, `digestAlgorithm` (`sha256` or `sha384`), `signatureAlgorithm` (`rsa-pkcs1-v1_5`, `rsa-pss` or `ecdsa`) and an opaque `state`; optional `stampStyle`, `rsaPadding` (`pkcs1` or `pss`), `reason`, `location` and `contactInfo` |
| `POST /sign/finish` | Builds the CMS around the token's signature and returns the signed PDF (PAdES B-T); a 422 when the TSA's token doesn't stamp the digest of that signature |
| `POST /finalize` | Revocation data for every signature and a document timestamp (PAdES B-LTA) |
| `POST /retimestamp` | Another document timestamp before the last one's certificate expires |

`keyUsage` on `/certificate` and `/validate` is `nonRepudiation`, the default, or `digitalSignature`. With `nonRepudiation` a certificate may sign only when its KeyUsage extension asserts nonRepudiation; with `digitalSignature`, when it asserts digitalSignature or nonRepudiation. A certificate without a KeyUsage extension never may, nor may a CA's certificate on `/certificate`. Any other value is a 422.

`reason`, `location` and `contactInfo` go into the signature dictionary as `/Reason`, `/Location` and `/ContactInfo`, which PDF viewers show in their signature panel. Each is trimmed and must then be 1 to 200 characters without control characters, or the request is a 422. They are written into the prepared PDF at `/sign/start`, so the state's MAC covers them and `/sign/finish` takes nothing more. The built-in stamp adds a `Reason:` line, wrapped to two lines and shortened past that.

The `state` from `/sign/start` is a JSON object passed back unchanged to `/sign/finish`. Its `output` member, base64 of the prepared PDF that `toSign` was computed for, is a stable part of this API: `@keyseal/server` reads it to serve the document to the helper. Every other member is opaque and may change.

The state's last member, `mac`, is an HMAC-SHA256 over the exact JSON text before it, keyed with HMAC-SHA256 of the label `keyseal-service sign state v1` under the bearer token. `/sign/finish` refuses a state whose MAC is missing or doesn't match with a 422 before reading anything in it, so no member can change, and a state from before the token was rotated is refused too.

Supported keys: RSA (PKCS#1 v1.5 or PSS with MGF1 and a 32-byte salt, SHA-256) and ECDSA P-256 or brainpoolP256r1 (SHA-256) and P-384 or brainpoolP384r1 (SHA-384), with ECDSA signatures as DER `ECDSA-Sig-Value`. PDFs are limited to 25 MB.

Bodies are capped as they stream in, so a chunked body is held to the same limits as one with a `Content-Length`: 25 MB for the raw PDF that `/validate`, `/finalize` and `/retimestamp` take, and 60 MB plus 16 KB for a JSON body. A larger body is a 413, and a `Content-Length` that isn't a non-negative decimal number is a 400.

`/validate` and `/finalize` refuse a PDF with more than 50 signatures and document timestamps with a 422. `/validate`, `/certificate`, `/finalize` and `/retimestamp` each get 45 seconds, fetches and the TSA's answer included; that's under the 60-second request timeout `@keyseal/server` uses by default. Past it they answer 422 too, except `/certificate`, which answers 504: there the cause is a slow revocation server, and `@keyseal/server` leaves a job for the helper to retry on anything but a 400 or 422. The budget cancels the work at its next await, so a synchronous step already running, such as parsing or pyHanko's diff analysis of one signature, finishes on its worker thread first. The 25 MB and 50-signature caps bound how long that can be.

A PDF no signature can be added to is a 422 that says why: an encrypted one, even when it opens without a password, on `/prepare`, `/sign/start`, `/finalize` and `/retimestamp`, and one certified with no changes allowed (DocMDP level 1) on `/prepare` and `/sign/start`. A certified PDF still takes revocation data and document timestamps, which PAdES allows.

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
| `SIGNING_EXTRA_TRUST_ROOTS_DIR` | none | Directory of `.pem`, `.cer`, `.crt` or `.der` certificates added to the bundled ones, or to `SIGNING_TRUST_ROOTS_DIR`'s; self-signed ones are roots, the rest intermediates |
| `SIGNING_ALLOW_FETCHING` | off | `true` lets validation fetch issuer certificates, OCSP and CRL data |
| `SIGNING_LOG_LEVEL` | `INFO` | Level of the service's own log records: `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`, in any case. They go to stderr as `LEVEL: logger: message`, beside uvicorn's own; any other value refuses to start. At `INFO` they include why `/certificate` refused a certificate |
| `TZ` | container's (UTC) | Time zone of the date in the built-in stamp, for example `Asia/Kolkata`; a zone name, since pyHanko refuses POSIX zones such as `IST-5:30` |

The default TSA is plain HTTP, as DigiCert serves no HTTPS endpoint for it. `/sign/finish` refuses a token whose imprint isn't the digest of the signature, but someone on the network path could still answer with a correctly imprinted token from another TSA. That shows up only at validation, and only where the TSA's trust is checked: `timestampValid` says the timestamp is intact and matches, not who issued it, and a token from any TSA chaining to a system root is trusted. Point `SIGNING_TSA_URL` at an HTTPS TSA to close the gap.

Revocation is checked soft-fail: a certificate whose CRL or OCSP data is missing or unreachable is still `trusted`. With fetching off, the default, no revocation data is fetched at all, so a revoked certificate is trusted unless a PDF carries the data that revokes it. `revocationChecked`, on `/certificate` and on each signature `/validate` reports, is true only when every certificate on the trusted path that names a CRL or OCSP responder had data that checked out; treat `trusted` without it as "chains to a configured root", not "not revoked".

With `SIGNING_ALLOW_FETCHING=true`, the URLs fetched come from the certificates being checked, so the service only connects to public IP addresses, over direct HTTP or HTTPS: every DNS answer and the address actually connected to must be public, each redirect is checked again, and proxies, proxy environment variables and cookies are not used. A response body past 8 MiB for a CRL or issuer certificate, or 64 KiB for an OCSP response, counted after decompression, is a failed fetch, so that data counts as unavailable and `revocationChecked` is false.

Setting `SIGNING_TRUST_ROOTS_DIR` replaces both the bundled CCA India roots and the bundled intermediates, so put every root and intermediate the chains need in that directory. The service refuses to start when the directory holds no readable root.

To trust another CA as well, such as a foreign or private one, keep the bundled set and point `SIGNING_EXTRA_TRUST_ROOTS_DIR` at a directory of its certificates instead. The service refuses to start when that directory can't be read or holds no readable certificate. `/health` counts its roots with the others.

## Plugins

Install a package into the image that declares entry points. A stamp style is a callable returning a pyHanko stamp style, chosen with `"stampStyle": "<name>"` on `/sign/start` (the built-in one is `signed-by`; an unknown name is a 400). The style's text parameters are `signer`, `reason`, `location` and `contact_info`, the last three empty when not given, so a `TextStampStyle` can show them with `%(reason)s`. A router factory takes the service's `Settings` and returns an `APIRouter`, mounted behind the bearer token. With fetching on, that `settings.validation` refuses to build a validation context: the public-only fetcher opens when the app starts, and only the built-in routes use it.

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

Released images are published as `ghcr.io/somus/keyseal-service`, for linux/amd64 and linux/arm64, tagged with the full version and with major.minor; pin the digest for an image that can't change ([docs/releasing.md](../docs/releasing.md#signing-service-image)).

```bash
docker run --rm -p 8080:8080 \
  -e SIGNING_SERVICE_TOKEN="$(openssl rand -base64 32)" \
  ghcr.io/somus/keyseal-service:0.4
```

To build it from a checkout instead, run `docker build -t keyseal-service service` and use `keyseal-service` as the image.

A derived image adds plugins and, if needed, its own roots:

```dockerfile
FROM ghcr.io/somus/keyseal-service:0.4
USER root
RUN uv pip install --python /app/.venv/bin/python acme-keyseal
USER signing
```

The bundled Geist font is under the SIL Open Font License; see `keyseal_service/fonts/OFL-Geist.txt`.
