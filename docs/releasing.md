# Releasing the helper

The npm packages and the signing service image release on their own: see
[releasing-npm.md](releasing-npm.md) and
[releasing-service.md](releasing-service.md).

A helper release is a tag, a draft made by CI, an offline signature by each
maintainer, and a manual publish. The signing rules are in
`docs/code-signing-policy.md`; the signing steps are in
`helper/packaging/sign-manifest.md`.

## Before the first release

- Run `scripts/set-github-owner.sh <owner>` to put the repository's owner
  in every repository URL that still names `OWNER` (the helper's `RELEASES` and
  catalogue URLs, the package manifests), and replace the placeholder in
  `RELEASE_KEYS` (`helper/crates/keyseal-core/src/update.rs`) and
  `CATALOGUE_KEYS` (`catalogue.rs`) with the real public keys. The release
  workflow refuses to run until they are real.
- Create the `release-macos` environment (required reviewer: a maintainer)
  with the secrets `APPLE_DEVELOPER_ID_P12` (base64 of the Developer ID
  Application certificate and key), `APPLE_DEVELOPER_ID_P12_PASSWORD`,
  `APPLE_API_KEY_P8` (the App Store Connect API key file's contents),
  `APPLE_API_KEY_ID` and `APPLE_API_ISSUER`, and the variable
  `APPLE_SIGNING_IDENTITY` ("Developer ID Application: Name (TEAMID)").
  Without `APPLE_SIGNING_IDENTITY` the workflow ad-hoc signs the macOS app
  and disk image instead of notarizing them, and Mac users approve the app
  once in System Settings, Privacy & Security, Open Anyway.
- Create the `release` environment with a maintainer as required reviewer.
- Protect `main` (changes only through reviewed pull requests) and add a
  tag ruleset for `helper-v*` (Settings, Rules, Rulesets, New tag ruleset,
  target pattern `helper-v*`) that restricts creation, updates and
  deletion to maintainers and blocks force pushes. The workflow also
  refuses a tag whose commit isn't on `main` or whose `RELEASE_KEYS`,
  `THRESHOLD` or `CATALOGUE_KEYS` differ from `main`'s
  (`helper/packaging/check-release-commit.sh`), but the ruleset keeps
  anyone else from making or moving release tags at all.
- Other releases in this repository (the driver catalogue, packages) must
  be published with `--latest=false`: helpers fetch
  `releases/latest/download/keyseal-update.json`.

## Steps

1. Set `version` in `helper/Cargo.toml` (`[workspace.package]`), update
   `Cargo.lock` (`cargo check` in `helper/`), and merge.
2. Tag the merge commit on `main` and push the tag. The tag must be
   `helper-v<version>` on a commit of `main`; the workflow fails otherwise.

   ```sh
   git tag helper-v1.4.0 && git push origin helper-v1.4.0
   ```

3. The `release` workflow builds the three platforms, waits for approval of
   `release-macos`, signs and notarizes the macOS app and disk image, and
   creates a draft release with:
   - `keyseal-helper-<v>-macos-universal.dmg` (download) and `.zip` (update)
   - `keyseal-helper-<v>-windows-x64.zip` (download) and `.exe` (update)
   - `keyseal-helper-<v>-linux-x64.tar.gz` and `keyseal_<v>_amd64.deb`
     (downloads) and `keyseal-helper-<v>-linux-x64.AppImage` (download and
     update). An AppImage replaces itself; a deb or tarball install keeps
     its binary, and the helper leaves the AppImage in its config
     directory with one notice per version.
   - `keyseal-update.json`, `SHA256SUMS`, `SHA256SUMS-unsigned`, `BUILDINFO`
4. Each signing maintainer reproduces the unsigned binaries (below),
   checks every asset against them, signs `keyseal-update.json` and
   `SHA256SUMS`, and sends their two signature entries (`sign-manifest.md`).
5. Combine the entries into `keyseal-update.json.sig` and `SHA256SUMS.sig`
   and check them (`sign-manifest.md`, step 6).
6. Run the `release` workflow by hand (Actions, release, Run workflow) with
   the tag and the contents of `keyseal-update.json.sig` and
   `SHA256SUMS.sig`. After approval of the `release` environment it checks
   the tag again, verifies both files' signatures with the pinned keys and
   threshold, checks every asset against `SHA256SUMS` and the update assets
   against the manifest, uploads the signatures and publishes the release
   as latest.
7. Installed helpers find the release within a day, or at once after a
   server refuses them with `426`.

## Reproducing a release

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
  in `.github/workflows/release.yml`):

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

## Toolchain upkeep

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
  SHA-256 in the workflow.
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
