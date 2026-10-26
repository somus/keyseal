<img src="brand/keyseal-icon.svg" width="96" alt="">

# KeySeal

KeySeal lets a web application sign PDFs with Indian Digital Signature Certificates (DSC) on USB tokens, without a browser extension or a localhost daemon. A signer clicks Sign on your page, a small desktop helper opens, shows who is asking and what will be signed, takes the token PIN and signs; your backend gets back a PAdES-signed PDF.

It is white-label: your page, your backend and your branding, with the helper and the signing service shared across integrators.

## How it works

```
 your page ──(your API)──> your backend ──────> signing service
   │  @keyseal/browser        @keyseal/server        pyHanko, private network
   │ keyseal:// link               ▲
   ▼                             │ job endpoint over HTTPS
 keyseal helper ───────────────────┘
   │
 USB token (PKCS#11, or CNG on Windows)
```

1. Your backend creates a sign job for one PDF, or up to 20 signed together, with `@keyseal/server` and hands the page a `keyseal://` link.
2. `@keyseal/browser` opens the link. The helper starts, checks the site (asking the signer to allow it on first contact) and claims the job.
3. The helper reads the signer's certificate from the token, and the backend has the signing service prepare every PDF and return the attributes to sign.
4. The helper checks those attributes and every downloaded PDF, shows the site, the documents and the signer, asks for the PIN once and signs them all on the token.
5. The signing service embeds each signature with a timestamp, and your backend receives the signed PDFs together, or none if any fails.

The helper never talks to the signing service, and the PIN never leaves the signer's computer.

## Components

| Component | Path | What it is |
| --- | --- | --- |
| Helper | [`helper/`](helper/) | Rust desktop app for macOS, Windows and Linux, on GPUI Kit. Finds the token's driver, enforces the trust rules and signs. |
| `@keyseal/server` | [`packages/server/`](packages/server/) | Fetch-API handlers for the manifest and job endpoint, and job creation. Runs on Bun, Node 22+ and Cloudflare Workers. |
| `@keyseal/browser` | [`packages/browser/`](packages/browser/) | Opens the link, watches the job and tells the page when to offer the helper download. No dependencies. |
| Signing service | [`service/`](service/) | pyHanko behind FastAPI in a Docker image: prepare, sign, validate, long-term validation data. |
| Driver catalogue | [`catalogue/`](catalogue/) | Signed list of DSC token drivers by USB id and platform (HYP2003, ePass2003, ProxKey, SafeNet and others). |
| Reference server | [`examples/reference-server/`](examples/reference-server/) | A minimal integrator backend, and the target of the end-to-end test. |
| Protocol | [`spec/`](spec/) | The `keyseal://` link, trust rules, manifest and job endpoint, with OpenAPI. |

## Get started

- **Integrating:** [docs/integrating.md](docs/integrating.md) walks through running the service, serving the job endpoint, creating jobs and starting the helper from your page.
- **How it's built:** [docs/design.md](docs/design.md) covers the protocol flow, the trust model and the token access rules; [spec/protocol-v1.md](spec/protocol-v1.md) is the normative protocol.
- **Working on keyseal:** [docs/development.md](docs/development.md) has the layout, prerequisites, checks and the end-to-end test.

## Supported tokens and keys

The helper loads PKCS#11 drivers from system and vendor directories only, matched to the plugged-in token through the driver catalogue, and falls back to the Windows certificate store (CNG) for keys on hardware. It signs with RSA (PKCS#1 v1.5 or PSS) and ECDSA P-256 or P-384 keys. Signatures are PAdES B-T, with B-LTA available from the service.

## Download

Signers install the helper from the [latest release](https://github.com/somus/keyseal/releases/latest): the disk image on macOS, the zip with `install.cmd` on Windows, and the AppImage, deb or tarball on Linux. It updates itself after that. Each release lists every file's SHA-256 in `SHA256SUMS`, signed by the maintainers.

The macOS app isn't notarized yet, so macOS asks once to allow it in System Settings, Privacy & Security, Open Anyway. The Windows exe isn't Authenticode signed either, so SmartScreen warns that it protected your PC; choose More info, then Run anyway. Every download is still listed in the maintainers' signed `SHA256SUMS`.

## Code signing policy

What is signed, by whom and with which keys, and how a release is checked before it is signed: [docs/code-signing-policy.md](docs/code-signing-policy.md). Windows builds are unsigned for now; SignPath Foundation declined the project's first application in October 2026, and it will apply again once the helper has a record of use.

## Privacy

The helper sends nothing about you or your computer to the KeySeal project. It talks to the site that opened a job: it fetches the job, its documents and the site's `/.well-known/keyseal.json`, and sends back the certificate you chose, the signature and, when a job fails, the reason. Once a day it fetches the update manifest and the driver catalogue from this repository's GitHub releases, which GitHub sees as ordinary downloads. Your PIN stays on your computer, and the private key never leaves the token. The sites you trusted, your settings and the logs stay on your computer.

## Status

Released. The helper, both packages, the signing service and the catalogue work end to end, including signing with real DSC tokens on macOS, CNG signing on Windows 11 and an automated end-to-end test with SoftHSM. Still to come: macOS notarization and Windows code signing ([docs/releasing.md](docs/releasing.md)).

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). The trust model and its known limits are in [docs/design.md](docs/design.md#trust-model).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE). The bundled Geist font is under the SIL Open Font License and the helper's interface icons are from Lucide (ISC). The KeySeal mark and app icons are in [brand/](brand/).
