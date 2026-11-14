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

#### Added

- With more than one token plugged in, KeySeal asks which one to use
  before asking for the PIN, and names that token in the PIN prompt. When
  the job names its certificate, the token holding it is used without
  asking. Before, KeySeal used the first token it found. `keyseal list` and
  `keyseal doctor` report every token.
- Enrolling a certificate proves the token holds its key: the helper signs a
  message bound to the site, the job and the certificate, and sends it with
  the certificate (spec section 8.6). No document is signed. On a token the
  PIN already entered covers it; from the macOS keychain or Windows, the
  system's or the token's PIN window now appears during enrolment.

#### Changed

- When the token holds several certificates, each one in the list shows
  the name, then who issued it, the last day it is valid and the end of
  its serial number, so a renewed certificate and the one it replaces no
  longer look the same.

#### Fixed

- Edge and Chrome on Windows name KeySeal, not "keyseal", for a helper that
  was first installed before 0.4.0. Windows had kept the old name in its
  cache; `keyseal install` and the first start after an update now clear it.
- On Windows, the first start after an update registers the helper again,
  as `keyseal install` does. Apps (Add or remove programs) shows the new
  version instead of the one first installed, and a helper installed before
  0.4.0 gets the Start menu shortcut and the Apps entry.
- With more certificates on the token than the window holds, the list no
  longer overlaps the document and signer above it. The window scrolls.

### [0.4.0][helper-0.4.0] - 2026-11-13

#### Added

- Every release asset has a build provenance attestation, which
  `gh attestation verify <file> --repo somus/keyseal` checks.
- Every package includes `THIRD-PARTY-NOTICES.txt`, the
  licences and notices of the open source crates the helper is built from.
- On Windows, `keyseal install` adds a KeySeal shortcut to the Start menu
  that opens the settings, and an entry under Apps (Add or remove programs)
  that uninstalls. `keyseal uninstall` removes both.
- On Windows and Linux, opening KeySeal without a link, from the Start
  menu, the app menu or the file manager, opens the settings. From a
  terminal it still prints the usage.
- The Linux desktop entry shows in the app menu, and `keyseal install`
  writes the packaged entry and its icon.
- `install.cmd /quiet` installs without waiting for a key and exits with
  the install's exit code.

#### Changed

- A wrong PIN on a PKCS#11 token no longer ends the job: the window clears
  the field and asks again in the same token session, until the signer
  enters the right PIN or cancels. The token's own counter is the only
  limit. Headless runs still try `KEYSEAL_PIN` once.
- The PIN prompt warns when one more wrong PIN will lock the token, and when
  a wrong PIN was entered before and few tries remain, reading the token's
  flags before each prompt.
- A token whose PIN is locked no longer shows the PIN field: the helper
  shows an error saying the token's own software or its issuer unlocks it,
  and reports the failure to the server.
- Certificates that have expired or aren't valid yet are no longer offered.
  When the token holds no other, the error says when its certificate
  expired, or from when it is valid, instead of the server refusing it
  after the PIN.
- A malformed `keyseal://` link shows a plain message to start again from
  the website instead of the URL parser's error.
- An empty Windows certificate store or macOS keychain shows in Settings and
  `keyseal doctor --json` as checked with nothing found, not as a driver
  that didn't work.
- A `KEYSEAL_PKCS11_MODULE` path with no file there is an error naming the
  variable and the path, not "no driver found".

#### Fixed

- Enter no longer submits the PIN before the Sign button responds, so a
  keystroke meant for another window can't confirm a signature.
- Links that arrive during a job reuse one busy message instead of opening
  a window each.
- A panic in the job shows an error window, is written to `keyseal.log` with
  where it happened, and is reported to the server once the job is claimed.
- The error shows at once when a job fails; the failure report to the server
  is sent alongside it, with its own 10 second limit, instead of first.
- On Windows, `keyseal uninstall` removes `%LOCALAPPDATA%\keyseal` once the
  helper has exited, instead of leaving the exe there. Only the helper's
  own files are deleted, and the folder only when it is then empty.
- Edge and Chrome on Windows name KeySeal when a site opens a `keyseal://`
  link, from the exe's new version information, instead of the bare scheme.
- The deb depends on the libraries the helper loads, so it installs and
  runs on a clean Ubuntu 22.04, Ubuntu 24.04 or Debian 12.
- A deb or tarball install no longer downloads the AppImage as its update
  and asks to copy it over the installed binary. It says once per version
  that a release is out, to install the way it was installed.
- A failed daily update check runs again after the next job instead of a
  day later.
- Size limits on downloads, such as 64 MiB for a document, count the bytes
  after a compressed response is decompressed, and a download exactly at
  the limit is accepted, as the protocol says.

### [0.3.0][helper-0.3.0] - 2026-11-05

#### Added

- On macOS, tokens that CryptoTokenKit exposes in the keychain, such as PIV
  cards and YubiKeys through macOS's own driver, sign when no PKCS#11 module
  reaches a token, as the Windows certificate store does. The helper asks for
  no PIN there: it shows the job and digests for confirmation, and macOS
  shows its own PIN dialog. `keyseal doctor` lists the keychain as a place
  it tried.
- Linux arm64 builds: an AppImage, which is also the update asset, a deb and
  a tarball, built and reproduced like the x64 ones. The helper looks for
  p11-kit modules in `/usr/lib/aarch64-linux-gnu/pkcs11` too.

### [0.2.0][helper-0.2.0] - 2026-11-04

#### Added

- Keys that need the PIN for every signature (`CKA_ALWAYS_AUTHENTICATE`)
  sign a whole job after one PIN: the helper keeps the PIN in a zeroising
  buffer until the job's signatures are made and logs in again before each
  one. On a PIN pad the reader asks once per document.
- RSA PKCS#1 v1.5 signing on tokens without `CKM_SHA256_RSA_PKCS` or
  `CKM_SHA384_RSA_PKCS`: the helper hashes the document and signs the
  DigestInfo with `CKM_RSA_PKCS`, giving the same signature.
- ECDSA keys on brainpoolP256r1 (with SHA-256) and brainpoolP384r1 (with
  SHA-384).
- `certificatePolicy.keyUsage`: with `digitalSignature`, a job also offers
  certificates whose key usage has digitalSignature without nonRepudiation.
  Without it, nonRepudiation is still required.

#### Changed

- Messages and the Linux desktop entry say "token or smart card" instead of
  "DSC token".

#### Fixed

- The trust prompt for an insecure test site is tall enough for its
  buttons, which the warning banner pushed out of the window.
- On Windows, the certificate store is used only when it holds a certificate
  with the job's key usage, so a store whose only hardware certificate has
  digitalSignature without nonRepudiation no longer fails a default job
  before a later place is tried.

### [0.1.4][helper-0.1.4] - 2026-11-04

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

#### Added

- `SIGNING_TSA_URL` takes a list of timestamp authorities, separated by
  commas or whitespace, asked in turn until one answers; one that failed is
  asked last for a minute. When none answers, `/sign/finish`, `/finalize`
  and `/retimestamp` answer 503, so `@keyseal/server` leaves the job for a
  retry. Before, `/sign/finish` answered 500 and the others 422. A value
  that isn't a list of http or https URLs refuses to start.
- `GET /ready` answers 200 when a timestamp authority answered lately, and
  503 when none did, for monitoring and an integrator's own "signing is
  unavailable" message. It needs no token, checks at most once a minute and
  names no authority.

### [0.4.0][service-0.4.0] - 2026-11-13

#### Added

- `SIGNING_LOG_LEVEL` sets the level of the service's own log records,
  `INFO` by default. Before, uvicorn left them unconfigured, so only
  warnings and errors appeared, without level or logger name.

#### Changed

- An encrypted PDF is a 422 saying so on `/prepare`, `/sign/start`,
  `/finalize` and `/retimestamp`, and a PDF certified with no changes allowed
  is one on `/prepare` and `/sign/start`. `/sign/start` answered 500 for a
  certified PDF and `/prepare` for an encrypted one, so `@keyseal/server`
  now fails the job with that message instead of answering 502.

- The system roots trusted beside the configured ones are read from
  OpenSSL's default CA bundle, the image's ca-certificates (the same set as
  before), so `SSL_CERT_FILE` and `SSL_CERT_DIR` now change them. oscrypto,
  unmaintained since 2022 and unable to detect OpenSSL 3.0.10 and later, is
  no longer a direct dependency; pyHanko still installs it but never imports
  it here.

#### Security

- pyHanko 0.38.1, which no longer loops forever on a PDF with a crafted
  cross-reference table and refuses one that lists an object twice in a
  section, which had weakened the check for changes made after a signature.
- `/certificate`, `/finalize` and `/retimestamp` stop after 45 seconds,
  fetches included, as `/validate` does, and `/finalize` refuses a PDF with
  more than 50 signatures. Each is a 422, except `/certificate`, which
  answers 504 so that `@keyseal/server` leaves the job for a retry.

### [0.3.0][service-0.3.0] - 2026-11-04

#### Added

- ECDSA keys on brainpoolP256r1 (SHA-256) and brainpoolP384r1 (SHA-384), as
  for P-256 and P-384.
- `keyUsage` on `POST /certificate` (body) and `POST /validate` (query):
  `nonRepudiation`, the default, or `digitalSignature`, which also accepts a
  certificate whose KeyUsage asserts digitalSignature only. A certificate
  without a KeyUsage extension never qualifies.
- `SIGNING_EXTRA_TRUST_ROOTS_DIR`, a directory of roots and intermediates
  trusted in addition to the bundled set or `SIGNING_TRUST_ROOTS_DIR`'s. The
  service refuses to start when it is unreadable or holds no certificate.

#### Changed

- `POST /certificate` refuses CA certificates whatever key usage they assert.

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

#### Changed

- Enrol jobs require the helper's proof of possession (spec section 8.6) and
  verify it after the certificate checks. This is breaking for helpers below
  0.5.0, which don't send it: their enrolments get 426 naming 0.5.0, or
  `minHelperVersion` if higher, and the job fails. A proof that doesn't
  verify gets 422 and fails the job.

### [0.5.0][server-0.5.0] - 2026-11-13

#### Added

- `keyseal.sweep()` expires old jobs and deletes their blobs, as creating a
  job does, and deletes the blobs of jobs that ended or are gone, which a
  failed or interrupted deletion used to leave forever. Call it from a
  scheduler.
- The `service` option takes any object with `ServiceClient`'s
  `certificate`, `signStart` and `signFinish` methods, typed as the new
  `SigningService`.
- `createSignJob` and `createEnrolJob` throw the new `InvalidJobInput` for
  input they refuse. It extends `TypeError`, so existing checks still
  match, and it tells a caller's mistake apart from an adapter's
  `TypeError`, such as a failed `fetch`.

#### Changed

- Adapters must implement `listBlobs()`, returning every stored blob key;
  `sweep()` uses it. The conformance suite checks it.
- A job is now stored before its PDFs, so a failure storing a PDF leaves a
  pending job that expires instead of no job.

#### Fixed

- `basePath` refuses `.` and `..` segments. URL parsing resolves them in the
  helper's requests, so no job URL under such a path could be reached.

### [0.4.0][server-0.4.0] - 2026-11-04

#### Added

- `certificatePolicy.keyUsage`: `"nonRepudiation"` (the default) or
  `"digitalSignature"`, which also accepts certificates whose KeyUsage asserts
  digitalSignature only. A policy of only `keyUsage` is valid. Certificates
  without KeyUsage and CA certificates never satisfy a policy.
- The job's key usage is sent to the signing service's `/certificate` check
  in both rounds, and `ServiceClient.validate(pdf, base, keyUsage)` passes
  one to `/validate`.
- brainpoolP256r1 (SHA-256) and brainpoolP384r1 (SHA-384) keys, parsed from
  the certificate DER and verified in TypeScript, since Bun and Workers lack
  these curves in `node:crypto`.
- `CertificateFacts` and `InspectedCertificate` report `keyUsage` and `ca`;
  new exported types `KeyUsage` and `EcCurve`.

#### Changed

- A custom `CertificateInspector` must now return `keyUsage` and `ca`.
- A job with a `certificatePolicy` but no `keyUsage` now also checks
  nonRepudiation locally, before asking the signing service.

### [0.3.0][server-0.3.0] - 2026-11-04

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

### [0.2.1][browser-0.2.1] - 2026-11-13

#### Fixed

- `watchJob` rejects with a `TypeError` for a status without a known
  `state`, or with a `message` that isn't a string, instead of polling until
  its timeout.

### [0.2.0][browser-0.2.0] - 2026-11-05

#### Changed

- `helperDownloadFor` takes `navigator` and returns a promise, and answers
  `linux-x64` or `linux-arm64` instead of `linux`. It asks Chromium's client
  hints for the architecture, because Chromium's user agent says x86_64 on
  every Linux machine, and reads the user agent in other browsers. Callers
  change `helperDownloadFor(navigator.userAgent)` to
  `await helperDownloadFor(navigator)` and link
  `keyseal-linux-arm64.AppImage` for `linux-arm64`.

### [0.1.3][browser-0.1.3] - 2026-11-04

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

### [4][catalogue-4] - 2026-11-05

#### Added

- `linux-arm64` module paths, for YubiKey (`ykcs11`) and OpenSC as Debian,
  Ubuntu and Fedora install them.

### [3][catalogue-3] - 2026-11-04

#### Added

- YubiKey PIV through Yubico's `ykcs11`, by USB id, and OpenSC for PIV,
  national eID and other smart cards, by path. OpenSC is listed after the DSC
  token drivers, since it also drives ePass2003 and HYP2003 tokens.

### [2][catalogue-2] - 2026-10-26

#### Added

- First signed catalogue, covering ePass2003, HYP2003 (HyperPKI), ProxKey,
  mToken CryptoID, InnaIT Key (PK32XX), SafeNet eToken 5110 and eToken PRO
  72K / SafeNet eToken 5100, and TrustKey.

[helper-unreleased]: https://github.com/somus/keyseal/compare/helper-v0.4.0...HEAD
[helper-0.4.0]: https://github.com/somus/keyseal/releases/tag/helper-v0.4.0
[helper-0.3.0]: https://github.com/somus/keyseal/releases/tag/helper-v0.3.0
[helper-0.2.0]: https://github.com/somus/keyseal/releases/tag/helper-v0.2.0
[helper-0.1.4]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.4
[helper-0.1.3]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.3
[helper-0.1.2]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.2
[helper-0.1.1]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.1
[helper-0.1.0]: https://github.com/somus/keyseal/releases/tag/helper-v0.1.0
[service-unreleased]: https://github.com/somus/keyseal/compare/service-v0.4.0...HEAD
[service-0.4.0]: https://github.com/somus/keyseal/compare/service-v0.3.0...service-v0.4.0
[service-0.3.0]: https://github.com/somus/keyseal/compare/service-v0.2.3...service-v0.3.0
[service-0.2.3]: https://github.com/somus/keyseal/compare/service-v0.2.2...service-v0.2.3
[service-0.2.2]: https://github.com/somus/keyseal/compare/service-v0.2.1...service-v0.2.2
[service-0.2.1]: https://github.com/somus/keyseal/compare/service-v0.2.0...service-v0.2.1
[service-0.2.0]: https://github.com/somus/keyseal/compare/service-v0.1.1...service-v0.2.0
[service-0.1.1]: https://github.com/somus/keyseal/compare/service-v0.1.0...service-v0.1.1
[service-0.1.0]: https://github.com/somus/keyseal/tree/service-v0.1.0
[server-unreleased]: https://github.com/somus/keyseal/compare/server-v0.5.0...HEAD
[server-0.5.0]: https://github.com/somus/keyseal/compare/server-v0.4.0...server-v0.5.0
[server-0.4.0]: https://github.com/somus/keyseal/compare/server-v0.3.0...server-v0.4.0
[server-0.3.0]: https://github.com/somus/keyseal/compare/server-v0.2.0...server-v0.3.0
[server-0.2.0]: https://github.com/somus/keyseal/compare/server-v0.1.1...server-v0.2.0
[server-0.1.1]: https://github.com/somus/keyseal/tree/server-v0.1.1
[browser-unreleased]: https://github.com/somus/keyseal/compare/browser-v0.2.1...HEAD
[browser-0.2.1]: https://github.com/somus/keyseal/compare/browser-v0.2.0...browser-v0.2.1
[browser-0.2.0]: https://github.com/somus/keyseal/compare/browser-v0.1.3...browser-v0.2.0
[browser-0.1.3]: https://github.com/somus/keyseal/compare/browser-v0.1.2...browser-v0.1.3
[browser-0.1.2]: https://github.com/somus/keyseal/compare/browser-v0.1.1...browser-v0.1.2
[browser-0.1.1]: https://github.com/somus/keyseal/tree/browser-v0.1.1
[catalogue-unreleased]: https://github.com/somus/keyseal/compare/catalogue...HEAD
[catalogue-4]: https://github.com/somus/keyseal/releases/tag/catalogue
[catalogue-3]: https://github.com/somus/keyseal/releases/tag/catalogue
[catalogue-2]: https://github.com/somus/keyseal/releases/tag/catalogue
