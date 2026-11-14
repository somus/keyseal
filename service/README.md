# KeySeal signing service

A pyHanko service behind FastAPI. It prepares PDFs with empty signature fields, returns the DER SignedAttributes a token signs, embeds the returned signature with a timestamp, validates signed PDFs and adds long-term validation data. The signer's key never reaches it; only the integrator backend talks to it, over a private network.

Every route except `GET /health` and `GET /ready`, plugin routes included, needs `Authorization: Bearer $SIGNING_SERVICE_TOKEN`. The token is checked before any of the body is read, and a missing or wrong one is a 401.

| Route | Does |
|---|---|
| `GET /health` | Liveness and the number of trust roots loaded |
| `GET /ready` | Whether the service can sign right now (below): 200 with `{"ready": true, "checks": {"tsa": "ok"}}`, or `"off"` with timestamps turned off; 503 with `{"ready": false, "checks": {"tsa": "unreachable"}}` |
| `POST /validate?base=<bytes>&keyUsage=<usage>` | Validation report for a PDF body; `base` adds what changed since the copy the signer was given, and `keyUsage` is the key usage a `trusted` signer's certificate asserts (below). Each signature's `timestampValid` is whether its signature timestamp is intact and matches the signature, `null` without one; a signature with an invalid timestamp makes the report `invalid` |
| `POST /certificate` | Whether a certificate chains to a configured root and may sign (`trusted`), and whether its revocation status was checked (`revocationChecked`); optional `keyUsage` (below) |
| `POST /prepare` | Adds empty signature fields as one incremental update |
| `POST /sign/start` | Reserves the signature and returns `toSign`, `digestAlgorithm` (`sha256` or `sha384`), `signatureAlgorithm` (`rsa-pkcs1-v1_5`, `rsa-pss` or `ecdsa`) and an opaque `state`; optional `stampStyle`, `rsaPadding` (`pkcs1` or `pss`), `reason`, `location` and `contactInfo` |
| `POST /sign/finish` | Builds the CMS around the token's signature and returns the signed PDF (PAdES B-T); a 503 when no timestamp authority answered, and a 422 when the only tokens it got don't stamp the digest of that signature |
| `POST /finalize` | Revocation data for every signature and a document timestamp (PAdES B-LTA); a 503 when no timestamp authority answered |
| `POST /retimestamp` | Another document timestamp before the last one's certificate expires; a 503 when no timestamp authority answered |

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
| `SIGNING_TSA_URL` | `http://timestamp.digicert.com` | RFC 3161 timestamp authorities, one or more http or https URLs separated by commas or whitespace and tried in that order (below); `none` turns timestamps off, and `/finalize` and `/retimestamp` then answer 503. Anything else refuses to start |
| `SIGNING_TRUST_ROOTS_DIR` | bundled CCA India roots and intermediates | Directory of `.pem`, `.cer`, `.crt` or `.der` certificates replacing the bundled ones; self-signed ones are roots, the rest intermediates |
| `SIGNING_EXTRA_TRUST_ROOTS_DIR` | none | Directory of `.pem`, `.cer`, `.crt` or `.der` certificates added to the bundled ones, or to `SIGNING_TRUST_ROOTS_DIR`'s; self-signed ones are roots, the rest intermediates |
| `SIGNING_ALLOW_FETCHING` | off | `true` lets validation fetch issuer certificates, OCSP and CRL data |
| `SIGNING_LOG_LEVEL` | `INFO` | Level of the service's own log records: `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`, in any case. They go to stderr as `LEVEL: logger: message`, beside uvicorn's own; any other value refuses to start. At `INFO` they include why `/certificate` refused a certificate |
| `TZ` | container's (UTC) | Time zone of the date in the built-in stamp, for example `Asia/Kolkata`; a zone name, since pyHanko refuses POSIX zones such as `IST-5:30` |

Each timestamp, on `/sign/finish`, `/finalize` and `/retimestamp`, asks the timestamp authorities in turn and takes the first token that stamps the digest it asked for. An authority that can't be reached, takes more than 10 seconds, answers with an HTTP error, a rejection or something unreadable, or stamps another digest counts as failed, and the next one is asked; one timestamp asks for at most 20 seconds in all, which keeps `/finalize` and `/retimestamp`, which ask twice, inside their 45 and `/sign/finish` inside the 60 `@keyseal/server` waits. An authority that failed is asked after the others for the next minute, so a dead first one costs its timeout once, not on every request. A failure followed by an answer is logged as a warning and every one failing as an error, naming the hosts. When none answered, the route answers 503, which `@keyseal/server` treats as an outage, leaving the job for the helper to retry; when the only tokens it got stamp another digest, it is a 422 that fails the job. A second authority is opt-in: list one only if its tokens are trusted wherever the PDFs are validated.

`GET /ready` says whether a timestamp authority answered lately. A timestamp the service got for a request in the last minute answers it, and so does one that couldn't be had from any authority; otherwise it asks the list for a timestamp, giving each authority 4 seconds, and that answer stands for the next minute, so probing every few seconds doesn't load a public TSA. Concurrent probes share one check, and a probe waits at most 10 seconds, answering 503 if the check hasn't finished by then. The body names no authority or error; the log does. Use it for monitoring and for showing your own "signing is unavailable" message, not as a load balancer's or Kubernetes readiness gate: a TSA outage hits every instance at once, and taking them all out of rotation would stop validation too, which needs no TSA. The image's `HEALTHCHECK` stays on `/health`.

The default TSA is plain HTTP, as DigiCert serves no HTTPS endpoint for it. `/sign/finish` refuses a token whose imprint isn't the digest of the signature, but someone on the network path could still answer with a correctly imprinted token from another TSA. That shows up only at validation, and only where the TSA's trust is checked: `timestampValid` says the timestamp is intact and matches, not who issued it, and a token from any TSA chaining to a system root is trusted. Point `SIGNING_TSA_URL` at an HTTPS TSA to close the gap.

Revocation is checked soft-fail: a certificate whose CRL or OCSP data is missing or unreachable is still `trusted`. With fetching off, the default, no revocation data is fetched at all, so a revoked certificate is trusted unless a PDF carries the data that revokes it. `revocationChecked`, on `/certificate` and on each signature `/validate` reports, is true only when every certificate on the trusted path that names a CRL or OCSP responder had data that checked out; treat `trusted` without it as "chains to a configured root", not "not revoked".

With `SIGNING_ALLOW_FETCHING=true`, the URLs fetched come from the certificates being checked, so the service only connects to public IP addresses, over direct HTTP or HTTPS: every DNS answer and the address actually connected to must be public, each redirect is checked again, and proxies, proxy environment variables and cookies are not used. A response body past 8 MiB for a CRL or issuer certificate, or 64 KiB for an OCSP response, counted after decompression, is a failed fetch, so that data counts as unavailable and `revocationChecked` is false.

What the service fetched is kept in memory for later requests, so `@keyseal/server`'s two certificate checks per sign job and the signers of one CA share a download. A CRL or OCSP response is reused until its own nextUpdate and never past it, and one without a nextUpdate isn't kept; issuer certificates are kept until evicted. The cache holds DER, at most 64 MiB in all, evicting the least recently used, and each request parses what it reuses, as it would a download. pyHanko checks the reused data exactly as fresh data, so a certificate revoked in it is refused and a check at a signature's timestamp still works. The cost is timeliness: a revocation the CA publishes before the kept data's nextUpdate is seen only once that passes, where a fresh fetch would see it as soon as the CA's CRL or responder carries it. Restarting the service empties the cache.

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
