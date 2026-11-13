# Releasing

Each component is versioned and released on its own, by pushing a tag:

| Component | Tag | Workflow |
| --- | --- | --- |
| [Helper](#helper) | `helper-vX.Y.Z` | `.github/workflows/release.yml` |
| [`@keyseal/server` and `@keyseal/browser`](#npm-packages) | `server-vX.Y.Z`, `browser-vX.Y.Z` | `.github/workflows/npm.yml` |
| [Signing service image](#signing-service-image) | `service-vX.Y.Z` | `.github/workflows/service.yml` |

Every release goes the same way:

1. Bump the component's version, move its Unreleased entries in
   `CHANGELOG.md` under the new version and date, and merge the pull
   request.
2. Wait for the `checks` and `e2e` runs on the merge commit on `main` to
   pass. Each workflow stops unless the tag is on `main`, matches the
   component's version, and both runs passed on that commit
   (`scripts/ci/ci-passed.sh`); if a run was still going, re-run the failed
   job once it has passed.
3. Tag the merge commit and push the tag, for example:

   ```sh
   git tag server-v0.2.0 && git push origin server-v0.2.0
   ```

## Helper

A helper release is a tag, a draft made by CI, an offline signature by each
maintainer, and a manual publish. The signing rules are in
`docs/code-signing-policy.md`; the signing steps are in
`helper/packaging/sign-manifest.md`.

### Repository setup

This is what the repository has in place for helper releases; check it
here before changing any of it.

- The release keys are pinned in `RELEASE_KEYS` with `THRESHOLD`
  (`helper/crates/keyseal-core/src/update.rs`) and the catalogue keys in
  `CATALOGUE_KEYS` (`catalogue.rs`). The fingerprints and custody rules are
  in `docs/code-signing-policy.md`.
- The `release` environment, with a maintainer as required reviewer, gates
  the publish run.
- The `release-macos` environment, with a maintainer as required reviewer,
  holds the macOS signing secrets `APPLE_DEVELOPER_ID_P12` (base64 of the
  Developer ID Application certificate and key),
  `APPLE_DEVELOPER_ID_P12_PASSWORD`, `APPLE_API_KEY_P8` (the App Store
  Connect API key file's contents), `APPLE_API_KEY_ID` and
  `APPLE_API_ISSUER`, and the variable `APPLE_SIGNING_IDENTITY`
  ("Developer ID Application: Name (TEAMID)"). Until the project has a
  Developer ID, `APPLE_SIGNING_IDENTITY` is unset, so the workflow ad-hoc
  signs the macOS app and disk image instead of notarizing them, and Mac
  users approve the app once in System Settings, Privacy & Security, Open
  Anyway.
- A branch ruleset on `main` allows changes only through reviewed pull
  requests.
- A tag ruleset on `helper-v*` restricts creating, updating and deleting
  release tags to maintainers and blocks force pushes. The workflow also
  refuses a tag whose commit isn't on `main` or whose `RELEASE_KEYS`,
  `THRESHOLD` or `CATALOGUE_KEYS` differ from `main`'s
  (`helper/packaging/check-release-commit.sh`), but the ruleset keeps
  anyone else from making or moving release tags at all.
- Every other release in this repository (the driver catalogue, packages)
  is published with `--latest=false`: helpers fetch
  `releases/latest/download/keyseal-update.json`.

To replace a key, make the new one with `helper/packaging/new-key.sh`,
change `RELEASE_KEYS` or `CATALOGUE_KEYS` in a reviewed pull request, and
release a helper signed by the keys the installed helpers already trust.
Helpers that install it trust the new key from then on. Rotation and
revocation are described in `docs/code-signing-policy.md`.

### Steps

1. Set `version` in `helper/Cargo.toml` (`[workspace.package]`), update
   `Cargo.lock` (`cargo check` in `helper/`), move the helper's Unreleased
   entries in `CHANGELOG.md` under the new version and date, and merge.
2. Once the checks have passed on it, tag the merge commit on `main` and
   push the tag. The tag must be `helper-v<version>`; the workflow fails
   otherwise.

   ```sh
   git tag helper-v1.4.0 && git push origin helper-v1.4.0
   ```

3. The `release` workflow builds the four platforms (Linux on x64 and arm64), waits for approval of
   `release-macos`, signs and notarizes the macOS app and disk image, and
   creates a draft release with:
   - `keyseal-helper-<v>-macos-universal.dmg` (download) and `.zip` (update)
   - `keyseal-helper-<v>-windows-x64.zip` (download) and `.exe` (update)
   - `keyseal-helper-<v>-linux-x64.tar.gz` and `keyseal_<v>_amd64.deb`
     (downloads) and `keyseal-helper-<v>-linux-x64.AppImage` (download and
     update), and the same for arm64: `keyseal-helper-<v>-linux-arm64.tar.gz`,
     `keyseal_<v>_arm64.deb` and `keyseal-helper-<v>-linux-arm64.AppImage`. An AppImage replaces itself; a deb or tarball install keeps
     its binary and downloads nothing, and the helper says once per
     version that the release is out.
   - `keyseal-update.json`, `SHA256SUMS`, `SHA256SUMS-unsigned`, `BUILDINFO`
   - the downloads again without the version, for fixed links:
     `keyseal-macos-universal.dmg`, `keyseal-windows-x64.zip`,
     `keyseal-linux-x64.AppImage`, `keyseal_amd64.deb`,
     `keyseal-linux-arm64.AppImage` and `keyseal_arm64.deb`

   Each of these files has a build provenance attestation
   ([Checking build provenance](#checking-build-provenance)).
4. Check, sign and publish with one script on a Mac, with Bitwarden
   unlocked, Docker running and cargo-about 0.9.3 installed
   (`cargo install --locked --features cli cargo-about@0.9.3`, once):

   ```sh
   export BW_SESSION="$(bw unlock --raw)"
   helper/packaging/release.sh 1.4.0
   ```

   Run it from an up-to-date checkout of `main`. It downloads the draft and
   clones the tag, and stops unless the tagged commit is on `main`, pins
   `main`'s keys and is the commit the release run built. It checks every
   asset the way `sign-manifest.md` describes, the Windows and macOS ones
   against that run's unsigned binaries, rebuilds the Linux binary in the
   pinned container, and stops at the first difference. Then it signs
   `keyseal-update.json` and `SHA256SUMS` with your release key, verifies
   the signatures with `verify-signatures.sh` (never by running the draft's
   helper, which could read `BW_SESSION`), and, once you confirm, starts
   the publish run. The Linux rebuild takes
   about 15 minutes under emulation; `--rebuild-host <ssh host>` runs it
   natively on an x86_64 Linux machine with Docker, in a throwaway
   container fed over SSH, and `--skip-rebuild` skips it. macOS and Windows aren't rebuilt: they need the
   Xcode, or the Visual Studio and Windows SDK, that `BUILDINFO` names
   (below).
5. Approve the `release` environment. The publish run checks the tag again,
   verifies both files' signatures with the pinned keys and threshold,
   checks every asset against `SHA256SUMS` and the update assets against
   the manifest, uploads the signatures and publishes the release as
   latest.
6. With a `THRESHOLD` above 1, each other maintainer runs the script with
   `KEYSEAL_SIGN_ONLY=1` and sends the two `.json` entries it writes;
   whoever publishes runs it with `KEYSEAL_RELEASE_DIR` set to a directory
   of their own and copies the entries into it first. Without it the script
   works in a new private directory each run.
7. Installed helpers find the release within a day, or at once after a
   server refuses them with `426`.

### Reproducing a release

Check out the tag and run the same script CI ran. The pinned Rust toolchain
comes from `helper/rust-toolchain.toml`; the platform C toolchain must match
what `BUILDINFO` in the draft records.

- macOS, on any Mac with the Xcode version in `BUILDINFO` selected
  (`DEVELOPER_DIR`) and the `x86_64-apple-darwin` target added:

  ```sh
  helper/packaging/build-release.sh macos-universal /tmp/keyseal-dist
  ```

  This also builds the x86_64 token worker, which `SHA256SUMS-unsigned`
  lists and the release puts in `KeySeal.app/Contents/MacOS/` beside the
  helper.

- Linux, in the same container image and rustup-init CI uses (both pinned
  in `.github/workflows/release.yml`). For arm64, use `--platform
  linux/arm64`, rustup-init's `aarch64-unknown-linux-gnu` build with SHA-256
  `a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697`, and
  `build-release.sh linux-arm64`; a Docker that won't pull the arm64 image by
  the index digest takes its own,
  `ubuntu@sha256:88881eb36da489f9ff8746ece8048ca16cc94f80e8cd3ae7e8335d8822631591`.

  ```sh
  docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src \
    ubuntu:22.04@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956 sh -c '
    apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates curl file git \
      pkg-config libasound2-dev libfontconfig-dev libvulkan1 libwayland-dev libx11-xcb-dev libxkbcommon-x11-dev &&
    curl -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.29.2/x86_64-unknown-linux-gnu/rustup-init &&
    echo "5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4  /tmp/rustup-init" | sha256sum -c - &&
    chmod +x /tmp/rustup-init && /tmp/rustup-init -y --profile minimal --default-toolchain none &&
    . "$HOME/.cargo/env" && git config --global --add safe.directory /src &&
    (cd helper && rustup toolchain install) &&
    helper/packaging/build-release.sh linux-x64 /src/dist-repro'
  ```

- Windows, in Git Bash on a machine with the Visual Studio, MSVC toolset
  and Windows SDK versions in `BUILDINFO` (the C runtime is linked in
  statically from the last two):

  ```sh
  helper/packaging/build-release.sh windows-x64 /tmp/keyseal-dist
  ```

Then compare:

```sh
sha256sum /tmp/keyseal-dist/keyseal-helper-*   # with SHA256SUMS-unsigned
```

The script maps the checkout, `CARGO_HOME` and target paths to fixed names,
strips symbols, and on macOS keeps object paths out of the Mach-O UUID, so
the result doesn't depend on where you build. Paths must not contain
spaces.

The signed macOS app can't match byte for byte; compare its executables
with yours using `helper/packaging/macos/compare-bundle.sh`
(`sign-manifest.md`, step 4).

### Third-party notices

The helper statically links crates whose licences ask for their notices to
go with the binary, so every package holds `THIRD-PARTY-NOTICES.txt`: the
Windows zip beside `keyseal.exe`, the macOS app in `Contents/Resources`,
the Linux tarball beside `keyseal`, and the deb and the AppImage under
`usr/share/doc/keyseal`.
The release run's `notices` job makes it once, with cargo-about 0.9.3 from
`Cargo.lock`, offline, so the same commit gives the same file anywhere.
`release.sh` makes it again from the tag and compares. To make it yourself,
with `cargo-about` 0.9.3 on the `PATH`:

```sh
helper/packaging/third-party-notices.sh /tmp/THIRD-PARTY-NOTICES.txt
```

`helper/packaging/about.toml` lists the licences accepted for every
crate, all permissive, and the few accepted for one crate only, with the
reason. A dependency under any other licence fails the release run's
`notices` job; review its licence before accepting it there.

### Checking build provenance

The draft run attests every asset it builds with `actions/attest`: a
signed statement, kept by GitHub and logged in Sigstore's public
transparency log, that the file came from `release.yml` running on the
tagged commit. Anyone can check a downloaded file with the GitHub CLI:

```sh
gh attestation verify keyseal-helper-1.4.0-linux-x64.AppImage --repo somus/keyseal \
  --signer-workflow somus/keyseal/.github/workflows/release.yml \
  --source-ref refs/tags/helper-v1.4.0
```

The attestation shows where a file was built; it isn't a release signature.
Helpers trust only `keyseal-update.json` signed by the pinned keys, and
`SHA256SUMS.sig` is what maintainers sign. The signatures added at publish
aren't attested.

### Toolchain upkeep

- Bump `helper/rust-toolchain.toml` and the version `checks.yml` installs
  together, in their own commit; the next release records the new version
  in `BUILDINFO`.
- The macOS jobs pin Xcode with `DEVELOPER_DIR` in
  `.github/workflows/release.yml`; change it when the runner image drops
  that Xcode.
- Linux builds run in the `ubuntu:22.04` container, so the binary needs
  glibc 2.35 or later. The container installs GPUI's build packages, the
  same list as `checks.yml`.
- The AppImage is built with appimagetool and runtime versions pinned by
  SHA-256 in the workflow, and `build-appimage.sh` fails unless the
  AppImage starts with that runtime.
- cargo-about is pinned by version and SHA-256 in the `notices` job
  (`.sha256` beside each archive on its GitHub release). Change the version
  in `third-party-notices.sh` and `release.sh` with it.
- Every action in `release.yml` is pinned by commit SHA with its version in
  a comment, the `ubuntu:22.04` image by digest, and rustup-init by version
  and SHA-256. Update a pin by resolving the new tag yourself
  (`gh api repos/actions/checkout/git/ref/tags/v7.0.1`, the registry's
  `docker-content-digest` for the image, `rustup-init.sha256` beside the
  binary on static.rust-lang.org), and update the `docker run` command
  above with the image and rustup-init.
- The container's apt packages are not pinned: `apt-get install` with
  exact versions breaks as soon as jammy-updates replaces one, so the build
  takes whatever jammy serves that day. A changed gcc or glibc headers can
  change the C objects (ring) and so the Linux binary; reproduce soon after
  the release, and compare the `cc` and `ldd` lines in `BUILDINFO` with
  yours if the hashes differ. Pinning them would mean pointing apt at a
  dated `snapshot.ubuntu.com` mirror.

## npm packages

`@keyseal/server` and `@keyseal/browser` are released by `npm.yml`, which
type-checks, tests and builds the package named by the tag and publishes it
with provenance.

### Steps

1. Bump `version` in `packages/server/package.json` or
   `packages/browser/package.json`, then release as above.
2. Check the run in Actions, then the package page on npmjs.com, which shows
   the provenance of the build.

### One-time setup

The workflow authenticates with trusted publishing (OIDC), so no npm token is
kept in GitHub. npm only lets you add a trusted publisher to a package that
already exists, so a new package's first version is published by hand:

1. Turn on two-factor authentication for your npm account, and be a member of
   the `keyseal` organisation.
2. Publish the first version from a clean checkout of main, answering the 2FA
   prompt:

   ```sh
   cd packages/server && bun run build && npm publish --access public
   ```

3. Add the trusted publisher, either from the package's Settings page on
   npmjs.com (repository `somus/keyseal`, workflow `npm.yml`, environment
   `npm`) or with npm 11.15 or later:

   ```sh
   npm trust github @keyseal/server --repo somus/keyseal --file npm.yml --env npm --allow-publish
   ```

4. On the package's Settings page, set Publishing access to "Require
   two-factor authentication and disallow tokens".

Every later version goes through the steps above.

## Signing service image

`service.yml` runs the service tests, builds `service/Dockerfile` for
linux/amd64 and linux/arm64, and pushes `ghcr.io/somus/keyseal-service`
tagged `X.Y.Z` and `X.Y`, with a build provenance attestation. No `latest`
tag is pushed.

### Steps

1. Bump `version` in `service/pyproject.toml` and run `uv lock` in
   `service/`, then release as above.
2. Check the run in Actions. Its summary lists the image digest; check the
   attestation against it:

   ```sh
   gh attestation verify oci://ghcr.io/somus/keyseal-service@sha256:<digest> --repo somus/keyseal
   ```

Integrators who want an image that can't move pin the digest,
`ghcr.io/somus/keyseal-service@sha256:<digest>`, rather than a tag.

### One-time setup

The workflow pushes with the workflow's `GITHUB_TOKEN`, so no registry token
is kept in GitHub. The first push creates the package as private and links it
to the repository through the image's `org.opencontainers.image.source`
label. After that run, open the package's settings
(github.com/users/somus/packages/container/keyseal-service/settings) and set
its visibility to public, so integrators can pull it without logging in.
