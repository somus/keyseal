# helper

The KeySeal desktop helper, in Rust. It handles `keyseal://sign?job=...` and `keyseal://enrol?job=...` links: it checks the link and the origin, asks the user to trust a new origin, claims the job, reads certificates from the user's PKCS#11 token, validates the SignedAttributes the server asks it to sign, shows the origin, title, signer, documents, certificate and digests, asks for the PIN once and returns a signature for every document of the job, all made in one token session. The protocol is [spec/protocol-v1.md](../spec/protocol-v1.md); section numbers in the code refer to it.

It ships the protocol core, a headless command line, the GPUI Kit windows, the `keyseal://` scheme registration, the driver catalogue, CNG on Windows, the document check and signed updates. The design and security rules are in [docs/design.md](../docs/design.md).

## Layout

A Cargo workspace with four crates.

`crates/keyseal-core`, the library the CLI and the GUI share:

| Module | What it does |
| --- | --- |
| `protocol` | Link parsing (3.3) and the job client: claim (checking that a sign job lists 1 to 20 documents, each at the job URL followed by `/documents/<index>`), certificate, signatures, document download and failure requests with `X-KeySeal-Version`, and the status codes of 8.8 turned into messages that name the origin |
| `origin` | Origin rules (4): https only, A-label hosts, no IP literals or localhost, and an HTTP agent whose resolver refuses other origins (so cross-origin redirects fail) and private addresses on every connection; at most 5 same-origin redirects; TLS against the system trust store; `KEYSEAL_ALLOW_INSECURE_ORIGINS` |
| `trust` | Trust on first use (5): `trust.json` in the config directory, one record per exact origin with the time it was trusted |
| `preferences` | The signer's choices from Settings, `preferences.json` in the config directory: transparent windows (on by default) and always showing the technical details (off); a missing or damaged file, or a missing setting, means the defaults |
| `manifest` | `/.well-known/keyseal.json` and its icon within 2 seconds (6), with the last good copy cached in `manifests/` |
| `cms` | SignedAttributes validation in strict DER against the posted certificate's hash (10), the key, digest and scheme pairings of 11.1, DER ECDSA-Sig-Value encoding |
| `token` | The `TokenBackend` trait the flow signs through (`pin_pad`, `pin_warning`, `certificates`, `login`, `sign`, `close`; `sign` takes every document of the job and finds the key once), `open`, which loads the module in process or in the worker, and PKCS#11 through cryptoki: certificates before and after login, key type cross-checked with the certificate, RSA PKCS#1 v1.5 (`CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`), RSA-PSS (`CKM_RSA_PKCS_PSS`, MGF1 with the digest, salt the digest's length), ECDSA (`CKM_ECDSA`, r\|\|s length checked) |
| `modules` | Where to look for the job's key, in order: `KEYSEAL_PKCS11_MODULE` alone when set; else the module in `config.json`, the driver catalogue's modules for plugged-in tokens, then for every token, the known DSC drivers for the OS and on Linux p11-kit's modules, each that is installed; then on Windows CNG, which comes first when a plugged-in token's catalogue entry has `cng`. Drivers load only from system and vendor directories (`/usr/lib`, `/usr/lib64`, `/usr/local/lib`, `/Library`, `/opt` and `/Applications` on macOS and Linux; `System32` and `Program Files` on Windows), never from user-writable places such as the home directory unless `KEYSEAL_PKCS11_MODULE` names them |
| `cng` | Windows only: the current user's `MY` store through CNG, tried when no PKCS#11 module reaches a token. Offers certificates that pass the same checks as on PKCS#11 (nonRepudiation, a supported key, not a CA) and whose key's provider is hardware or removable (`NCRYPT_IMPL_TYPE_PROPERTY`), and signs with `NCryptSignHash`: PKCS#1 v1.5 and PSS (salt the digest's length) padding named by the digest, ECDSA r\|\|s encoded as on PKCS#11, every document of a job through one key handle. The vendor's provider shows its own PIN dialog, attached to the window the `Ui` names (`NCRYPT_WINDOW_HANDLE_PROPERTY`) when it names one |
| `worker` | Intel-only macOS drivers: reads the Mach-O header of the module without loading it, and when the helper runs as arm64 and the module has only an x86_64 slice, runs the token operations in `keyseal-token-worker` over JSON lines on its stdin and stdout, a job's documents in one `Sign` request. The PIN travels as hex, which JSON carries without escaping, and a reply longer than 4 MiB is refused. The worker is reaped on a background thread, since some drivers take seconds to unload |
| `flow` | The sign and enrol state machine over a `Ui` trait (`confirm_origin`, `choose_certificate`, `prompt_pin`, `confirm_digest`, `confirm_enrol`, `show_error`, `show_info`, `window_handle`), whose failures say whether the user cancelled; every document of a sign job is checked before the PIN and signed after one login; and the backend choice: each place `modules` lists in turn, moving on when a module fails to load or sees no token, or the store holds no signing certificate on hardware. The PIN stays in zeroising buffers from the `Ui` to the login |
| `update` | Updates (13): after a job, at most daily or at once after a `426` or a `minHelperVersion` refusal, reads the latest release's `keyseal-update.json`, verifies it with `verify_threshold` over Ed25519 signatures from the pinned keys, downloads the newer build for this platform, checks its hash and stages it in the config directory. The next launch verifies the staged build again, installs the verified bytes and runs the new build with the same arguments. The Linux update is the AppImage, which replaces the AppImage the helper runs from as a whole file (`APPIMAGE`) and never a deb or tarball install. Where the helper isn't replaced (outside an AppImage on Linux, or a folder that can't be written), the build is left in the config directory and a window says where, once per version |
| `doctor` | What `keyseal doctor` reports: the config directory and trusted origins, the GPU, the driver catalogue, USB devices with the catalogue token each one is, every driver path, and each attempt a job would make through `flow::open_backend` with how it went. One `Report` holds the rows the settings window shows (devices, drivers with their state: used, no token, failed with the reason, missing, not tried; and the outcome) and the report text. `in_child` runs `keyseal doctor --json` and reads the report, so a driver that crashes or hangs never takes a window with it; a child still running after 30 seconds is stopped and the window says so |
| `install` | `keyseal install` and `uninstall`: the `keyseal://` scheme for this user, without administrator rights (Launch Services on macOS, `HKCU\Software\Classes` on Windows, a desktop entry and `xdg-mime` on Linux) |
| `macos` | Registers the app bundle with Launch Services, and reads the `keyseal://` link from the launch Apple Event for a headless run |

Certificates are filtered before anyone chooses (8.2): by `expectedCertificateSha256`, then by `certificatePolicy`, whose policy OIDs, issuer CN and subject O `protocol` reads with x509-parser. When the policy leaves none, the job fails with "None of the certificates on this token are accepted by <origin> for this job."

Sign jobs take one of the two paths of 12.1. If the token shows a signing certificate before login, the helper posts it, validates round 1 and shows everything with the digests in the PIN prompt. If it shows none, the PIN comes first, and after round 1 a second prompt shows the certificate and digests and needs an explicit confirm before signing; declining logs out and fails the job.

A sign job carries 1 to 20 documents. Round 1 returns one `toSign` per document; the helper validates each, downloads each document (64 MiB each, 256 MiB together) and checks it against its digest, and any failure stops the job before the PIN or the confirm, with nothing signed. After the one PIN, `TokenBackend::sign` signs every document in the same session and round 2 posts the signatures together.

`crates/keyseal-ui`, the windows, on GPUI Kit (`gpui-kit` 0.8.0, which brings `gpui-component` 0.8.0 and pins the GPUI snapshot `gpui-pre` =0.3.9, zed@93d7456; AccessKit 0.24 is always on in that snapshot). GPUI needs Rust 1.93 or later. `native.rs` holds each platform's look: light or dark as the system is, the accent, type size, radii, heading weight and dialog button order (primary last on macOS, first on a footer band on Windows 11, full width on GNOME), and glass on macOS (a blurred window under a transparent title bar), opaque when the system's Reduce transparency is on, the signer turns it off in Settings or a job's manifest has `translucent: false`. The icons are a few Lucide SVGs in `icons/` (ISC licence alongside), plus KeySeal's own mark for the About section of Settings. `keyseal-helper/build.rs` embeds `packaging/windows/keyseal.ico` in `keyseal.exe` as icon resource 1, which GPUI gives its windows; a cross build from macOS or Linux needs `llvm-rc` on the `PATH` for the icon and builds without it otherwise.

| Window | What it shows |
| --- | --- |
| Trust prompt | First contact (5): the origin's host in A-label form (with the port when it isn't the default) as the heading, "wants to use KeySeal for the first time", one line of advice, Allow and Cancel. No branding, and Allow is not the default button. Escape cancels; Enter doesn't allow |
| Job | Branding from the manifest when there is one, never outweighing the origin: the name in small text, the icon as the header tile with a sign or enrol badge, and the accent colour on the top border, the primary button, the focus ring and the selection (reset before any trust prompt). Then the host and what it asks, then the document title and signer. The certificate subject and the digest (lowercase hex grouped by 8) sit under "Show technical details", shown from the start when the signer turned on "Always show technical details" in Settings. A batch asks to "sign several documents", its first row says how many ("12 documents") over the job's title, then a numbered list of the documents' titles, to which the details add each digest beside its title; the list takes the height left in a taller window and scrolls inside itself, so the PIN field and the buttons stay in view with 20 documents; Sign stays one button for the whole batch. A masked PIN field with the token's retry warning, Cancel and Sign. The login-first path shows it twice: PIN first, then Confirm. Several fitting certificates are a list in the same window. Enter submits the PIN; it never confirms a signature or a certificate choice, which take a click or Space on the focused button. Escape cancels |
| Message | The flow's error with a status icon and Close; for "no driver found" it also says to open KeySeal on its own, which shows Settings with the tokens and drivers it found. Not shown when the user cancelled a prompt: the failure is reported to the server and the helper exits. The same window says where an update was left for the user to install, and that KeySeal is busy when a link arrives during a job |
| Settings | Trusted sites with a Forget button each. Tokens and drivers: what `keyseal doctor` finds, checked in a `keyseal doctor --json` process on the background executor each time the window opens or Refresh is pressed, with a busy row meanwhile: whether a job could use a token now, each plugged-in catalogue token with its driver's state in plain words (working, doesn't see the token, didn't work with the reason, not installed), the other installed drivers that loaded or failed, and Copy diagnostics, which puts the whole report text on the clipboard for a support request. Signing: an Always show technical details switch. On macOS, Appearance: a Transparent windows switch. Both switches are saved in `preferences.json`. An About section with the KeySeal mark and version, and the config directory; from the app menu (Settings..., cmd-,) or `keyseal settings`. A second request focuses the open window |

The flow runs on a background thread. Each `Ui` call sends a request to the main thread, where GPUI runs, and blocks until the user answers; closing a window answers Cancel, and once the job window is closed every later prompt of the job does too. When the job is over its windows close and, at most once a day, the driver catalogue is downloaded before the process exits; a failed download is only logged, and nothing is downloaded while the catalogue key in `catalogue.rs` is the placeholder. Links that reach the running app (macOS sends later links to it) start a job once the previous job's windows have closed; the process exits after the last job. All strings are in `src/strings.rs`.

On CNG the helper never asks for a PIN. A sign job takes the second path's confirmation: after round 1 the helper shows the origin, title, signer, documents, certificate and digests and needs an explicit confirm, then the vendor's PIN dialog appears during `NCryptSignHash`. Every document of a job is signed through one key handle, so a provider that keeps the handle authenticated, as smart card providers do, asks once per job; a provider whose policy asks for the PIN on every signature asks once per document, which the helper can't change. The batch path has been type-checked for Windows, not yet run on a Windows token. An enrol job shows the origin, title and signer, with Continue, before the store is read (12.2), then always the certificate choice before anything is sent.

CNG signing has been checked on Windows 11 with a TPM virtual smart card through Edge, Chrome and Firefox, not yet with a vendor DSC token. The unit tests cover the filtering and the signature encoding against a fake store; Windows code type-checks from macOS or Linux with `cargo xwin clippy --target x86_64-pc-windows-msvc --all-targets` ([cargo-xwin](https://github.com/rust-cross/cargo-xwin) supplies the MSVC headers `ring` builds against).

`crates/keyseal-helper`, the `keyseal` binary:

```
keyseal run <keyseal://link>       run a job in the windows, or headless with KEYSEAL_HEADLESS=1
keyseal settings                 the settings window
keyseal list                     certificates on the token
keyseal doctor                   what the helper sees
keyseal doctor --json            the same report as JSON, which the settings window reads
keyseal doctor --forget <origin> stop trusting an origin
keyseal install                  register the keyseal:// scheme for this user
keyseal uninstall                remove that registration
keyseal update                   look for an update now
keyseal update verify <manifest> <signatures>
                               verify an update manifest with the pinned keys
keyseal --version
```

`crates/keyseal-token-worker`, the `keyseal-token-worker` binary: the x86_64 process the helper starts under Rosetta for an Intel-only driver. It sits beside the helper's executable; [packaging/README.md](packaging/README.md) has the build.

## Environment

| Variable | Effect |
| --- | --- |
| `KEYSEAL_HEADLESS=1` | `run` without windows. Prompts go to stderr; the outcome to stdout; the exit code is 0 on success |
| `KEYSEAL_PIN` | The PIN for headless runs, used once per job and never retried. `list` uses it to log in when no certificate is visible without login |
| `KEYSEAL_HEADLESS_TRUST_ORIGIN` | A headless run accepts a first contact only with this exact origin, for example `https://dash.example.org`; any other new origin is refused before any request |
| `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` | Development and CI: also allows `http://localhost` and `http://127.0.0.1` on any port. Such origins skip the private-address check, are never stored as trusted and are flagged as insecure in every prompt |
| `KEYSEAL_PKCS11_MODULE` | Absolute path of the PKCS#11 module to load instead of the known drivers |
| `KEYSEAL_CONFIG_DIR` | Replaces the config directory (the platform config directory's `keyseal`, e.g. `~/Library/Application Support/keyseal`), which holds `trust.json`, `preferences.json`, `manifests/` and `keyseal.log` |

## Windows and logging

Without `KEYSEAL_HEADLESS`, `run` opens the windows and exits with 0 when the job is signed or enrolled, 1 otherwise. On macOS, `keyseal` started without arguments and without a terminal (as the `keyseal://` handler is) takes the link from the open-URL event, or opens the settings window if none arrives within a second. With `KEYSEAL_HEADLESS=1` it reads the link from that event itself. Windows and Linux pass the link as the only argument. Since a helper started by the browser has no terminal, the window path writes what it reports to stderr and to `keyseal.log` in the config directory (started afresh past 1 MB); the link (it holds the job token) and the PIN are never logged.

There is no fallback UI. When no GPU can be used (no Metal device on macOS, or the window can't be created elsewhere), `keyseal` says so on stderr and in the log and exits with 1. `doctor` prints the Metal device on macOS. A panic while the windows start, such as GPUI failing to set up DirectX, is also written to the log.

On Windows `keyseal.exe` is a GUI program, so a browser starting it opens no console window. Run from a terminal, it prints to that terminal, but only a batch script such as `install.cmd` waits for it: at a `cmd` or PowerShell prompt the prompt comes back at once and the exit code isn't set. Where the output or the exit code matters, as for `doctor` or a headless run, use `start /wait keyseal doctor` in `cmd` (then `%ERRORLEVEL%`) or `(Start-Process keyseal -ArgumentList doctor -Wait -NoNewWindow -PassThru).ExitCode` in PowerShell.

A headless run against a local reference server:

```bash
KEYSEAL_HEADLESS=1 KEYSEAL_PIN=1234 \
  KEYSEAL_ALLOW_INSECURE_ORIGINS=1 KEYSEAL_HEADLESS_TRUST_ORIGIN=http://127.0.0.1:3000 \
  KEYSEAL_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
  cargo run -p keyseal-helper -- run 'keyseal://sign?job=http%3A%2F%2F127.0.0.1%3A3000%2Fv1%2Fjobs%2F<token>'
```

## doctor

`keyseal doctor` prints the helper version, OS and architecture, the config directory and trusted origins, the GPU (macOS), whether insecure origins are allowed, every module path (missing or found), then each attempt a job would make and how it went (used, failed to load, can't run here naming its architectures, no token; on Windows also CNG), where the used module runs (in this process, or in the token worker with its path), and the certificates visible before login. It exits non-zero when nothing is installed or every attempt failed for another reason than a missing token. With no token plugged in it says so and exits 0. Settings shows the same report under Tokens and drivers, with Copy diagnostics for the text. `keyseal doctor --forget https://dash.example.org` deletes that origin's trust record.

## Develop and test

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
# End to end against SoftHSM; needs softhsm2-util, pkcs11-tool (OpenSC) and openssl
KEYSEAL_SOFTHSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so cargo test -p keyseal-helper --test softhsm
```

`crates/keyseal-ui` tests the strings table, digest grouping and host form, and opens every window headlessly through GPUI's `TestAppContext` to drive it with clicks and keys, the settings window with a sample doctor report. `crates/keyseal-core/tests/http.rs` runs the job client and manifest fetch against a server in the test. The SoftHSM test runs `keyseal run` against a two-round server in the test with RSA-2048 (PKCS#1 v1.5 and PSS, SHA-256 and SHA-384), P-256 and P-384 keys, verifies each signature with openssl, and covers the login-first path with a token whose certificate is a private object, a batch of three documents signed after one login on both paths, wrong PINs, tampered SignedAttributes, mismatched algorithms, a batch with one tampered document, enrolment and untrusted origins.

To preview a window with sample data in any platform's look, run the `gallery` example; [docs/development.md](../docs/development.md#previewing-the-windows) has the commands.
