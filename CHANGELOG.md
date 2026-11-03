# Changelog

Each KeySeal component is versioned and released on its own, so this file has
one section per component, newest release first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A pull request that changes what users of a component see adds a line under
that component's Unreleased heading. The release pull request moves those
lines under the new version with the release date.

- [Helper](#helper) (`helper-v*` tags)
- [Signing service](#signing-service) (`service-v*` tags)
- [@keyseal/server](#keysealserver) (`server-v*` tags)
- [@keyseal/browser](#keysealbrowser) (`browser-v*` tags)
- [Driver catalogue](#driver-catalogue) (`catalogue` release)

## Helper

### [Unreleased][helper-unreleased]

#### Fixed

- On macOS, a standard user who can't write to `/Applications` is told about
  an update the helper can't install, instead of the helper downloading the
  same update every day. The update is left in the config directory with one
  notice per version, as on Linux, and update failures are written to
  `keyseal.log`.
- `keyseal doctor` says which connections use a proxy: update and catalogue
  downloads honour the proxy environment variables, and the job connection
  never does.

#### Security

- The config directory is created with mode 0700 and the files in it with
  0600 on macOS and Linux.
- The certificate chain sent with a signature or enrolment holds only the
  signing certificate's issuers, not every other certificate on the token.
- More special-purpose address ranges are refused for site connections,
  including IPv4 addresses embedded in IPv4-mapped, NAT64 and 6to4 IPv6
  addresses.
- On Windows, `reg.exe` is run from the system directory instead of being
  looked up on `PATH`.

#### Changed

- The .deb recommends `desktop-file-utils`, so the `keyseal://` handler
  registers on minimal systems.
- GPUI Kit 0.9.0 (GPUI snapshot gpui-pre 0.3.11) and ureq 3.5.1, with the
  other dependencies at their latest compatible versions.

### [0.1.3][helper-0.1.3] - 2026-10-27

#### Security

- The trust prompt and the job window ignore their confirming buttons for
  700 ms after they appear, come forward or change stage, so a keystroke meant
  for the page can't trust an origin.

#### Fixed

- The AppImage embeds the pinned AppImage runtime.

### [0.1.2][helper-0.1.2] - 2026-10-26

#### Added

- Each download is also published under a fixed name
  (`keyseal-macos-universal.dmg`, `keyseal-windows-x64.zip`,
  `keyseal-linux-x64.AppImage`, `keyseal_amd64.deb`), so sites can link to
  `releases/latest/download/<name>`. The helper itself is unchanged.

### [0.1.1][helper-0.1.1] - 2026-10-26

#### Changed

- The job window opens as soon as the origin is trusted and shows the step
  the job is at. Cancel, or closing the window, closes it at once.
- KeySeal comes to the front whenever it opens a window.

#### Fixed

- The helper tries IPv4 before IPv6 and caps each connection attempt, so
  networks with an unreachable IPv6 route no longer delay every job.

### [0.1.0][helper-0.1.0] - 2026-10-26

#### Added

- First release, for macOS (universal), Windows (x64) and Linux (x64
  AppImage, deb and tarball). The macOS app is ad-hoc signed until the
  project has a Developer ID, and the Linux build is reproducible.

## Signing service

### [Unreleased][service-unreleased]

### [0.2.3][service-0.2.3] - 2026-11-04

#### Security

- Fetched CRLs are capped at 8 MiB and OCSP responses at 64 KiB; a larger
  body counts as a failed fetch, so revocation is reported as unchecked.
- `/validate` refuses a PDF with more than 50 signatures and stops after
  45 seconds, with a 422 in both cases.

#### Changed

- The image's base layers are pinned by digest (python:3.15-slim and uv
  0.13.7), and the locked dependencies are at their latest versions.

### [0.2.2][service-0.2.2] - 2026-11-03

#### Fixed

- `/sign/finish` refuses with a 422 a timestamp token whose message imprint
  isn't the digest of the signature, instead of embedding it.
- `/validate` reports `timestampValid` for each signature (`null` without a
  timestamp) and counts a signature with an invalid timestamp as invalid.

### [0.2.1][service-0.2.1] - 2026-10-27

#### Fixed

- pyHanko work runs off the event loop, so a slow signing or validation
  request no longer stalls the others.

### [0.2.0][service-0.2.0] - 2026-10-27

#### Added

- `/certificate` and each `/validate` signature report `revocationChecked`:
  whether revocation data for every certificate on the trusted path checked
  out.

#### Security

- Rendering digests resolve each indirect PDF object once, so a crafted
  document can't take exponential time.
- The PKCS#1 fallback refuses keys beyond OpenSSL's limits.
- Posted certificates load strictly, so bytes after the DER are refused.

### [0.1.1][service-0.1.1] - 2026-10-26

#### Fixed

- With `SIGNING_ALLOW_FETCHING=true`, the certificate check retries without
  fetching when OCSP and CRL servers time out, instead of refusing the
  certificate as untrusted, and logs why it refuses one.

### [0.1.0][service-0.1.0] - 2026-10-26

#### Added

- First image published to `ghcr.io/somus/keyseal-service` for linux/amd64
  and linux/arm64, with a build provenance attestation.

#### Security

- Certificate, OCSP and CRL fetches go only to public addresses, with each
  redirect checked again.
- The bearer token is checked before any route reads the request body, and
  bodies are capped, chunked ones included.

## @keyseal/server

### [Unreleased][server-unreleased]

#### Added

- `@keyseal/server/testing` exports `runAdapterConformance` and
  `adapterConformanceChecks`, a framework-neutral suite to run against your
  adapter.

#### Changed

- The package ships the repository's LICENSE and its `src`, so the
  `@keyseal/source` export condition resolves for consumers.
- The README documents the adapter contract (millisecond `leaseStartedAt`,
  one atomic `expireOlderThan`), that enrolment has no proof of possession,
  that the types need TypeScript 5.7 or later, and that Cloudflare Workers is
  untested and suits small documents at most.

### [0.2.0][server-0.2.0] - 2026-10-27

#### Added

- `CertificateFacts` and `ValidatedSignature` carry `revocationChecked` from
  the signing service, which needs service 0.2.0 or later. Sign jobs check
  the certificate again in round 2 and refuse one revoked since round 1.

#### Security

- A certificate is accepted only as exactly one DER certificate. Before, a
  forged PEM certificate appended to a trusted DER one could be reported in
  `certificatePolicy` and `CertificateFacts`.

### [0.1.1][server-0.1.1] - 2026-10-26

#### Changed

- First version published from CI, with npm provenance.

### 0.1.0 - 2026-10-26

- First release, published by hand.

## @keyseal/browser

### [Unreleased][browser-unreleased]

#### Changed

- The package ships the repository's LICENSE and its `src`, so the
  `@keyseal/source` export condition resolves for consumers.
- The README states that the types need TypeScript 4.7 or later.

### [0.1.2][browser-0.1.2] - 2026-11-03

#### Changed

- `onNotClaimed` is described as "the helper hasn't picked up the job yet",
  not "the helper isn't installed": an installed helper can still be showing
  its trust prompt. Integrators should show a download link beside the job's
  status rather than in place of it.
- The documentation notes that a Content Security Policy must allow
  `keyseal:` in `frame-src`, and the README's download links point at the
  latest release's fixed names.

### [0.1.1][browser-0.1.1] - 2026-10-26

#### Changed

- First version published from CI, with npm provenance.

### 0.1.0 - 2026-10-26

- First release, published by hand.

## Driver catalogue

The catalogue is published as the `catalogue` release; its version is the
`version` field in `catalogue/catalogue.json`.

### [Unreleased][catalogue-unreleased]

### [2][catalogue-2] - 2026-10-26

#### Added

- First signed catalogue, covering ePass2003, HYP2003 (HyperPKI), ProxKey,
  mToken CryptoID, InnaIT Key (PK32XX), SafeNet eToken 5110 and eToken PRO
  72K / SafeNet eToken 5100, and TrustKey.

[helper-unreleased]: https://github.com/somus/keyseal/compare/helper-v0.1.3...HEAD
[helper-0.1.3]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.3
[helper-0.1.2]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.2
[helper-0.1.1]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.1
[helper-0.1.0]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.0
[service-unreleased]: https://github.com/somus/keyseal/compare/service-v0.2.3...HEAD
[service-0.2.3]: https://github.com/somus/keyseal/compare/service-v0.2.2...service-v0.2.3
[service-0.2.2]: https://github.com/somus/keyseal/compare/service-v0.2.1...service-v0.2.2
[service-0.2.1]: https://github.com/somus/keyseal/compare/service-v0.2.0...service-v0.2.1
[service-0.2.0]: https://github.com/somus/keyseal/compare/service-v0.1.1...service-v0.2.0
[service-0.1.1]: https://github.com/somus/keyseal/compare/service-v0.1.0...service-v0.1.1
[service-0.1.0]: https://github.com/somus/keyseal/tree/service-v0.1.0
[server-unreleased]: https://github.com/somus/keyseal/compare/server-v0.2.0...HEAD
[server-0.2.0]: https://github.com/somus/keyseal/compare/server-v0.1.1...server-v0.2.0
[server-0.1.1]: https://github.com/somus/keyseal/tree/server-v0.1.1
[browser-unreleased]: https://github.com/somus/keyseal/compare/browser-v0.1.2...HEAD
[browser-0.1.2]: https://github.com/somus/keyseal/compare/browser-v0.1.1...browser-v0.1.2
[browser-0.1.1]: https://github.com/somus/keyseal/tree/browser-v0.1.1
[catalogue-unreleased]: https://github.com/somus/keyseal/compare/catalogue...HEAD
[catalogue-2]: https://github.com/somus/keyseal/releases/tag/catalogue
