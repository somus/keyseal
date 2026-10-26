# Design

KeySeal lets a web application sign PDFs with Indian Digital Signature Certificates (DSC) held on USB tokens, without a browser extension or a localhost daemon. This document records the design and the security rules the code follows. The wire protocol is specified normatively in [spec/protocol-v1.md](../spec/protocol-v1.md); where the two differ, the spec wins.

## Audience

- Indian NGO and trust dashboards.
- CA firms and compliance portals.
- SaaS products that need signatures on contracts, HR documents or lending paperwork.

Out of scope: government-style portals. KeySeal does not coexist with emSigner flows and does not lock the helper to an origin by default.

## Components

| Component | Location | Summary |
| --- | --- | --- |
| Helper | `helper/` | Rust desktop app on GPUI Kit, launched through `keyseal://`. Talks to the token and to the integrator's job endpoint. |
| `@keyseal/server` | `packages/server/` | Fetch-API `Request`/`Response` handlers for the manifest and the job endpoint, plus job creation. An adapter supplies job storage, blobs and the completion callback. |
| `@keyseal/browser` | `packages/browser/` | Opens the `keyseal://` link, watches the job and tells the page when no helper claimed it. |
| Signing service | `service/` | pyHanko behind FastAPI, shipped as a Docker image. Prepares PDFs, builds the CMS around the token's signature, validates and timestamps. |
| Driver catalogue | `catalogue/` | Signed list of DSC token drivers by USB id and platform, updated separately from the helper. |
| Reference server | `examples/reference-server/` | Minimal integrator backend wiring `@keyseal/server` to the service. The end-to-end test drives it. |
| Spec | `spec/` | Protocol specification, OpenAPI and the decisions it settled. |

The helper never talks to the signing service; only the integrator backend does, so service credentials and document handling stay on the server side.

Everything lives in one repository so a protocol change lands as one pull request across the helper, the packages, the service and the spec. The protocol is versioned `v1` in the job URL and the manifest; the packages and the helper follow SemVer independently of it.

A branded, origin-locked helper build is a parameterised build option, published only when an integrator asks for one.

## Protocol

### Two-round flow

1. The integrator backend creates a job and the page opens a `keyseal://` link carrying the job URL and its one-time token.
2. The helper `GET`s the job. The server marks it claimed and returns a claim nonce, the job description and optional constraints: `expectedCertificateSha256` pins one certificate, and `certificatePolicy` asks for policy OIDs, issuing CAs or a subject organization where no certificate can be pinned yet.
3. The helper filters the token's certificates by those constraints and `POST`s the chosen one. The server enforces the same constraints on what it receives.
4. The server prepares every PDF of the job through the service and returns each one's DER SignedAttributes, with one `digestAlgorithm` and `signatureAlgorithm` for all of them.
5. The helper validates every SignedAttributes (contentType, messageDigest, signing-certificate-v2), downloads every prepared PDF and checks that its last `/ByteRange` hashes to its messageDigest, shows the origin, title, signer, documents and certificate, asks for the PIN once, signs every document in the same token session and `POST`s the signatures with the claim nonce.
6. The server verifies every signature, finishes every PDF through the service and only then calls the adapter's `onCompleted` with all of them.

A sign job carries 1 to 20 documents; one document is a list of one. A batch is all or nothing: a document that fails any check stops the job before the PIN, one signature that doesn't verify fails the job before anything is finished, and the integrator never receives part of a batch.

Enrol, capturing a certificate without signing, is a single round: `GET` the job, then `POST` the certificate and chain. What the integrator stores from it is their policy.

### Job token and lifecycle

- The token is opaque and single use, and only its hash is stored.
- Jobs live 15 minutes. Completing a job takes a 5 minute settle lease: the request handling a completion holds the job for at most 5 minutes, after which a repeated completion may take it over. The lease doesn't limit how long the helper may take within the job's lifetime.
- The `claimed` state drives install detection: if no claim arrives within about 5 seconds, the page shows the download link while the job stays open, so a fresh install can still pick it up.

### Versioning

- The manifest carries `"protocol": 1` and job URLs contain `/v1/`. The `keyseal://` link carries only the job URL, so it is versioned through the URL it points at.
- The helper sends `X-KeySeal-Version` on every request. The server may refuse helpers below a minimum version with `426`, which is also how updates are forced.

### Algorithms

RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256 and ECDSA P-384. RSA-PSS uses MGF1 with the message digest and a salt as long as the digest. P-256 signs SHA-256 and P-384 signs SHA-384; ECDSA signatures travel as DER `ECDSA-Sig-Value`.

## Trust model

- Trust on first use per exact origin, on any first contact, sign or enrol.
- The first-contact prompt shows the domain only, never branding, so a manifest can't dress up an unknown origin.
- The trust store keeps the exact origin and the time it was trusted. Users revoke it with `keyseal doctor --forget <origin>` or from the settings window.
- Branding (a name, a same-origin PNG icon up to about 256 KB and one accent colour) comes from the manifest per job within a 2 second budget, with the last good copy cached. Branding never appears above the origin, and a branding change never prompts again.
- Server origins must be HTTPS on a domain name. IP literals, `localhost` and private address ranges are refused, on every connection, which also blocks DNS rebinding. Cross-origin redirects are not followed.
- For development and CI, `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` in the helper's environment admits `http://localhost` and `http://127.0.0.1`. Those origins are never stored, so they prompt on every job, and the windows show an insecure-origin banner. Nothing else relaxes the origin rules.
- Manifests may never name driver paths; choosing a module is the helper's decision alone.
- HTTPS proxies are not supported, because the resolved-address check can't run through a proxy. The helper ignores proxy environment variables and `keyseal doctor` says so.
- The catalogue and the directory scan load modules only from system and vendor library directories. A path in the helper's own `config.json` may point anywhere, since writing that file is explicit consent. `/usr/local/lib` counts as a vendor directory on macOS because token installers write there.
- Known limit: on macOS, admin users can write to `/Applications`, and Intel Homebrew makes `/usr/local` user-owned, so the directory rule is weaker there than on Linux and Windows. The helper does not check file ownership, because vendor installers vary.
- SoftHSM is never in the default scan; CI and developers point `KEYSEAL_PKCS11_MODULE` at it.

## Helper

### Token access

Module resolution, in order:

1. `KEYSEAL_PKCS11_MODULE` in the environment (development and CI). When set, it is the only candidate.
2. The module path in the helper's `config.json`.
3. The driver catalogue's modules for the USB ids of the connected tokens.
4. The catalogue's other module paths for this platform.
5. The built-in list of known DSC driver paths.
6. p11-kit's configured modules, on Linux.
7. CNG, on Windows. A catalogue entry can mark a token as CNG-first.

The helper uses the first candidate that loads and sees a token, not the first whose file exists, so a stale or broken driver doesn't hide a working one.

On Windows, CNG (`NCryptSignHash`) signs with keys in hardware or removable key storage providers only. The vendor's PIN dialog is accepted there; the helper shows the origin, title, signer, certificate and digests and asks for an explicit confirm before handing off. A batch is signed through one key handle, so a provider that keeps the handle authenticated asks for the PIN once per job; one that asks on every signature by its own policy asks once per document.

Intel-only macOS drivers run in a separate x86_64 worker process that speaks JSON over pipes, shipped inside the universal app.

PIN handling: the retry warning is shown where the driver exposes it, the PIN is never retried automatically and asked once per job however many documents it has, it stays in zeroising buffers from the window to the login, and tokens with a PIN pad use the protected authentication path.

### What you see is what you sign

Before asking for the PIN, the helper validates every document's SignedAttributes in strict DER and checks that each prepared PDF's last `/ByteRange` covers the whole file except the signature gap and hashes to its messageDigest. It does not render pages. The windows show the document's title and signer up front, and the certificate and digest under "Show technical details". For a batch the row says how many documents there are, and the details list each document's title with its digest, in a list that scrolls inside the window.

### Windows and look

The windows are built with GPUI Kit and follow the platform: light or dark as the system is, the platform's accent, type size and dialog button layout, and on macOS a blurred glass window under a transparent title bar. There is no fallback UI: when no GPU is available, `keyseal doctor` names what is missing and the page points the user to another way to sign.

English only, with every string in one table (`helper/crates/keyseal-ui/src/strings.rs`). System font fallback covers other scripts in document titles and names.

### Platforms

- macOS universal app, notarized.
- Windows x64, unsigned in release one; SignPath Foundation signing is planned after it.
- Linux tarball with an xdg handler, AppImage and deb, unsigned, using p11-kit.

## Releases and updates

- Release manifests are signed offline with maintainers' Ed25519 keys, since cloud KMSs lack Ed25519. The keys are software keys in Bitwarden for now, moving to YubiKeys later (see [code-signing-policy.md](code-signing-policy.md#key-custody)).
- A manifest carries N signatures, and the helper verifies a threshold over a pinned key set. The threshold is 1-of-N until a second maintainer exists.
- The driver catalogue is signed by a separate single-maintainer key and hosted in the repository's GitHub releases.
- Unsigned binaries are reproducible from a pinned toolchain and lockfile, with hashes recorded per release, and maintainers rebuild and compare before signing. See [releasing.md](releasing.md) and [code-signing-policy.md](code-signing-policy.md).
- The helper checks for updates at most daily with a 5 second budget, downloads in the background after a job and applies the update on the next launch. A server's minimum-version refusal still forces an update.

## Signing service

- The generic image bundles the CCA India roots and known intermediates. `SIGNING_TRUST_ROOTS_DIR` replaces both.
- It refuses to start with a weak bearer token: shorter than 32 characters or with fewer than 10 distinct characters.
- `/prepare` adds empty signature fields only. `/sign/start` takes a `stampStyle` name; stamp styles and extra FastAPI routers register through Python entry points, so an integrator can add document-specific routes in a derived image.
- The default timestamp authority is DigiCert's free TSA, configurable with `SIGNING_TSA_URL`.

## TS packages

- `@keyseal/server` is framework-neutral and runs anywhere `Request` and `Response` exist (Bun, Node 22+, Cloudflare Workers).
- `@keyseal/browser` has no runtime dependencies. It polls the integrator's status endpoint by default; server-sent events are optional.
