# Development

## Repository layout

| Path | What | Toolchain |
| --- | --- | --- |
| `helper/` | Desktop helper, a Cargo workspace (`keyseal-core`, `keyseal-helper`, `keyseal-ui`, `keyseal-token-worker`) and its release packaging | Rust, pinned in `helper/rust-toolchain.toml` |
| `packages/server/` | `@keyseal/server` | Bun, TypeScript |
| `packages/browser/` | `@keyseal/browser` | Bun, TypeScript |
| `service/` | Signing service | Python 3.12+, uv |
| `catalogue/` | Driver catalogue and its build and signing tools | Bun, TypeScript (standalone package) |
| `examples/reference-server/` | Reference integrator backend | Bun |
| `spec/` | Protocol specification and OpenAPI | |
| `scripts/` | Test certificates and the CI scripts | bash |
| `docs/` | Design, integration, development and release docs | |

Each component's README covers its internals: [helper](../helper/README.md), [server](../packages/server/README.md), [browser](../packages/browser/README.md), [service](../service/README.md), [catalogue](../catalogue/README.md).

## Prerequisites

- Rust via rustup (the toolchain file picks the version), Bun 1.4, Python 3.12+ with uv, and Docker for the end-to-end test.
- For the helper's token tests: SoftHSM 2, OpenSC (`pkcs11-tool`) and OpenSSL. On macOS, `brew install softhsm opensc openssl@3`; on Debian and Ubuntu, `apt install softhsm2 opensc`.
- On Linux, GPUI's build dependencies: `libasound2-dev libfontconfig-dev libvulkan1 libwayland-dev libx11-xcb-dev libxkbcommon-x11-dev`.

## Checks

These are the checks CI runs in `.github/workflows/checks.yml`.

TypeScript, from the repository root:

```sh
bun install --frozen-lockfile
(cd catalogue && bun install --frozen-lockfile)
bun run check:types && (cd catalogue && bun run check:types)
bun run lint
bun run format:check
bun run test
```

Service:

```sh
cd service
uv sync --frozen
uv run pytest
```

Helper:

```sh
cd helper
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy -p keyseal-ui --all-targets --features gallery -- -D warnings
cargo test
# The SoftHSM suite runs only with a module path:
KEYSEAL_SOFTHSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so cargo test -p keyseal-helper --test softhsm
```

On Debian and Ubuntu the SoftHSM module is `/usr/lib/softhsm/libsofthsm2.so`. Windows-only code can be type-checked from macOS or Linux with [cargo-xwin](https://github.com/rust-cross/cargo-xwin): `cargo xwin clippy --target x86_64-pc-windows-msvc --all-targets -- -D warnings`.

## End-to-end test

`scripts/ci/e2e.sh` is the end-to-end CI job and runs locally as well. It builds the signing service image and runs it in Docker with a throwaway CA as its only trust root, starts the reference server with Bun, creates a SoftHSM token with RSA-2048, P-256 and P-384 certificates, and has the headless helper complete a sign job for each key, a batch job of three documents, enrol jobs and jobs that must fail on a wrong expected certificate or an unmet certificate policy, checking that every signed PDF validates as intact and trusted and has the `/Reason` its job passed in `signatureDetails`.

It needs docker, bun, cargo, curl, jq, openssl, softhsm2-util and pkcs11-tool. Run `bun install` first, then:

```sh
KEYSEAL_SOFTHSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so scripts/ci/e2e.sh
```

## Running the helper against a local server

The helper refuses plain-HTTP origins unless `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` is set in its environment, and the server needs `allowInsecureOrigin: true`. With the reference server running (see its README), start a job from its page, or run a link headless:

```sh
cd helper
KEYSEAL_ALLOW_INSECURE_ORIGINS=1 KEYSEAL_HEADLESS=1 KEYSEAL_PIN=1234 \
  KEYSEAL_HEADLESS_TRUST_ORIGIN=http://127.0.0.1:8787 \
  KEYSEAL_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
  cargo run -p keyseal-helper -- run 'keyseal://sign?job=...'
```

A headless run accepts a first contact only with the origin in `KEYSEAL_HEADLESS_TRUST_ORIGIN`. The helper's README lists every environment variable. `keyseal doctor` shows what the helper sees: driver paths, tokens, trusted origins and the GPU.

## Previewing the windows

The `gallery` example opens one window with sample data, in this platform's look or another's:

```sh
cd helper
cargo run -p keyseal-ui --example gallery --features gallery            # lists the views
cargo run -p keyseal-ui --example gallery --features gallery -- pin-details
KEYSEAL_GALLERY_LOOK=windows KEYSEAL_GALLERY_APPEARANCE=dark \
  cargo run -p keyseal-ui --example gallery --features gallery -- trust
```

`KEYSEAL_GALLERY_LOOK` takes `mac`, `windows` or `gnome`, and `KEYSEAL_GALLERY_APPEARANCE` takes `light` or `dark`. The look's tokens are in `helper/crates/keyseal-ui/src/native.rs`; a real check still needs the platform, since fonts, title bars and glass come from the OS.

## App icons

The app icons are generated from the SVGs in [brand/](../brand/) by `scripts/make-icons.sh`; see [brand/README.md](../brand/README.md).

## Conventions

- Commits follow Conventional Commits (`fix(helper): ...`, `feat(server): ...`, `docs: ...`); see [CONTRIBUTING.md](../CONTRIBUTING.md).
- A protocol change updates `spec/`, the helper, the packages and the service in the same pull request.
- Windows strings live in `helper/crates/keyseal-ui/src/strings.rs`, in plain English.
