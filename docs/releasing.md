# Releasing

Each component is versioned and released on its own:

| Component | Tag | Workflow |
| --- | --- | --- |
| [Helper](#helper) | `helper-vX.Y.Z` | `.github/workflows/release.yml` |
| [`@keyseal/server` and `@keyseal/browser`](#npm-packages) | `server-vX.Y.Z`, `browser-vX.Y.Z` | `.github/workflows/npm.yml` |
| [Signing service image](#signing-service-image) | `service-vX.Y.Z` | `.github/workflows/service.yml` |
| [Driver catalogue](../catalogue/README.md#publishing) | none: the `catalogue` release, updated in place | none |

The driver catalogue is signed and uploaded by hand, as its README
describes; `scripts/release.sh` doesn't touch it. Every other release goes
the same way, by pushing a tag:

1. Bump the component's version, move its Unreleased entries in
   `CHANGELOG.md` under the new version and date, and merge the pull
   request. The sections below say where each version lives.
2. From a clean checkout of `main` at that merge commit, run the release
   script on a Mac:

   ```sh
   git switch main && git pull
   scripts/release.sh --dry-run   # the plan, changing nothing
   scripts/release.sh
   ```

   It reads each component's version from the checkout, finds out from
   GitHub what is left to do, and prints that as a plan. When a helper
   release is due it asks for your Bitwarden master password once, at the
   start; nothing after that needs you. It then waits for the `checks` and
   `e2e` runs on the commit's push to `main` to pass, pushes the tags not
   yet on GitHub, checks, signs and publishes the helper
   ([Helper](#helper)), and waits for the npm and service runs its tags
   started. A `server-v` tag waits until the helper released with it is
   published and latest, since a server version can require that helper.
   It ends with what it released, the terminal bell and a macOS
   notification, on failure too.

   The plan comes from what GitHub holds, not from an earlier run: a tag
   that isn't on GitHub is pushed, a helper whose release is missing or a
   draft is checked, signed and published, and a published helper is done.
   After a failure, fix the cause and run it again to carry on. The rebuild
   flags `--rebuild-boat`, `--rebuild-local`, `--rebuild-host <ssh host>`
   and `--skip-rebuild` go through to `helper/packaging/sign-release.sh`
   ([Rebuild modes](#rebuild-modes)).

Each workflow stops unless the tag is on `main`, matches the component's
version, and both runs passed on that commit (`scripts/ci/ci-passed.sh`).

### By hand

The script only automates what follows. Once the `checks` and `e2e` runs
on the merge commit have passed (if a workflow ran while they were still
going, re-run its failed job once they have passed), tag the merge commit
and push the tag, for example:

```sh
git tag server-v0.2.0 && git push origin server-v0.2.0
```

For a helper, push its tag, then run `helper/packaging/sign-release.sh` (step 4
below), and push a `server-v` tag only after the helper release is
published.

## Helper

A helper release is a tag, a draft made by CI, an offline signature by each
maintainer, and a manual publish. The rules it follows, from which commit
may be released to what must match before anyone signs, are in
[docs/code-signing-policy.md](code-signing-policy.md); this section is the
procedure.

### Repository setup

- The `release-macos` environment holds the macOS signing secrets
  `APPLE_DEVELOPER_ID_P12` (base64 of the Developer ID Application
  certificate and key), `APPLE_DEVELOPER_ID_P12_PASSWORD`,
  `APPLE_API_KEY_P8` (the App Store Connect API key file's contents),
  `APPLE_API_KEY_ID` and `APPLE_API_ISSUER`, and the variable
  `APPLE_SIGNING_IDENTITY` ("Developer ID Application: Name (TEAMID)").
  Until the project has a Developer ID, `APPLE_SIGNING_IDENTITY` is unset,
  so the workflow ad-hoc signs the macOS app and disk image instead of
  notarizing them, and Mac users approve the app once in System Settings,
  Privacy & Security, Open Anyway.
- The environments, rulesets and pinned keys, and why they are set so,
  are in the policy: [Release environments](code-signing-policy.md#release-environments),
  [Which commits are released](code-signing-policy.md#which-commits-are-released)
  and [Key custody](code-signing-policy.md#key-custody). Check there before
  changing any of them.
- No other release in this repository may be marked latest:
  [catalogue/README.md](../catalogue/README.md#publishing).

### Steps

1. Set `version` in `helper/Cargo.toml` (`[workspace.package]`), update
   `Cargo.lock` (`cargo check` in `helper/`), move the helper's Unreleased
   entries in `CHANGELOG.md` under the new version and date, and merge.
2. Run `scripts/release.sh` (above). Once the checks have passed it
   pushes the tag, `helper-v<version>`, which starts the release workflow,
   and runs steps 4 and 5. The rest of this section is what those steps
   do, and how to run them by hand.
3. The `release` workflow builds the four platforms (Linux on x64 and
   arm64), signs the macOS app and disk image (ad hoc until the project
   has a Developer ID, then notarized), and creates a draft release with:
   - `keyseal-helper-<v>-macos-universal.dmg` (download) and `.zip` (update)
   - `keyseal-helper-<v>-windows-x64.zip` (download) and `.exe` (update)
   - `keyseal-helper-<v>-linux-x64.tar.gz` and `keyseal_<v>_amd64.deb`
     (downloads) and `keyseal-helper-<v>-linux-x64.AppImage` (download and
     update), and the same for arm64: `keyseal-helper-<v>-linux-arm64.tar.gz`,
     `keyseal_<v>_arm64.deb` and `keyseal-helper-<v>-linux-arm64.AppImage`.
     An AppImage replaces itself; a deb or tarball install keeps its
     binary and downloads nothing, and the helper says once per version
     that the release is out.
   - `keyseal-update.json`, `SHA256SUMS`, `SHA256SUMS-unsigned`, `BUILDINFO`
   - the downloads again without the version, for fixed links:
     `keyseal-macos-universal.dmg`, `keyseal-windows-x64.zip`,
     `keyseal-linux-x64.AppImage`, `keyseal_amd64.deb`,
     `keyseal-linux-arm64.AppImage` and `keyseal_arm64.deb`

   Each of these files has a build provenance attestation
   ([Checking build provenance](#checking-build-provenance)).
4. `helper/packaging/sign-release.sh` checks, signs and publishes on a Mac,
   with Bitwarden logged in, cargo-about 0.9.3 installed
   (`cargo install --locked --features cli cargo-about@0.9.3`, once), and
   what the [rebuild mode](#rebuild-modes) needs: by default Docker running
   and the `boat` CLI signed in. `scripts/release.sh` runs it; on its own:

   ```sh
   helper/packaging/sign-release.sh 1.4.0
   ```

   Run it from an up-to-date checkout of `main`. It asks for the Bitwarden
   master password unless `BW_SESSION` is set, and hands the session only
   to `bw` and `sign-file.sh`. It waits for the tag's release run to make
   the draft; when GitHub cancelled one of its jobs because no hosted
   runner took it, as happens when macOS runners are short, it runs the
   failed jobs again, once. It then runs every check in the policy's
   [Before signing](code-signing-policy.md#before-signing-reproducibility),
   stopping at the first difference, signs `keyseal-update.json` and
   `SHA256SUMS` with your release key, verifies the signatures with
   `verify-signatures.sh` (never with the draft's helper), starts the
   publish run (step 5), waits for it, and stops unless the release is then
   published and latest.

   `--verify-only` runs every check and stops before signing, without
   Bitwarden, on a draft or a published release; on a published one it
   also verifies the signatures the release carries. Anyone can use it to
   check a release:

   ```sh
   helper/packaging/sign-release.sh 1.4.0 --verify-only
   ```

5. The publish run checks the tag again, verifies both files' signatures
   with the pinned keys and threshold, checks that the draft holds exactly
   the assets `SHA256SUMS` lists and that they match it and the manifest,
   uploads the signatures and publishes the release as latest.
6. Installed helpers find the release within a day, or at once after a
   server refuses them with `426`.

### Rebuild modes

The two Linux architectures rebuild at the same time, each in a throwaway
container, with the build output in `rebuild-<platform>.log` in the work
directory. Where they run:

- By default, x64 in a Boat sandbox made for this run, with none of your
  stored secrets and deleted when the script exits (2 to 3 minutes on a
  `large` sandbox), and arm64 in Docker on the Mac, natively on Apple
  silicon (about 5 minutes). The whole script took under 10 minutes for
  0.5.0.
- `--rebuild-boat`: both in Boat sandboxes, arm64 in the same arm64
  container under QEMU user emulation (Ubuntu's `qemu-user-static`), since
  Boat machines are x86_64. The Mac needs no Docker, but arm64 takes about
  40 minutes.
- `--rebuild-local`: both in Docker on the Mac; x64 is emulated there and
  takes about 15 minutes.
- `--rebuild-host <ssh host>`: both natively on an x86_64 Linux machine
  with Docker, in throwaway containers fed over SSH.
- `--skip-rebuild`: no rebuild.

What each mode is independent of, and what skipping it gives up, is in the
policy's [Before signing](code-signing-policy.md#before-signing-reproducibility).

### Signing with more than one key

With a `THRESHOLD` above 1, each other maintainer runs `sign-release.sh` with
`KEYSEAL_SIGN_ONLY=1`, which checks, signs and stops, and sends whoever
publishes the two entries it leaves in its work directory,
`keyseal-update.json-<login>.json` and `SHA256SUMS-<login>.json`. The
publisher sets `KEYSEAL_RELEASE_DIR` to a directory of their own (without
it the script uses a new private one each run), copies the entries into
it, and runs the script, which adds theirs and combines every entry with
`jq -cs '{signatures: .}'` into `keyseal-update.json.sig` and
`SHA256SUMS.sig`.

`sign-release.sh` signs only with the key in Bitwarden. To sign with a backup
key, check the draft in a directory of your own, then sign, combine,
verify and publish by hand from it, without running the draft's helper:

```sh
export KEYSEAL_RELEASE_DIR="$HOME/keyseal-release-1.4.0"
helper/packaging/sign-release.sh 1.4.0 --verify-only && cd "$KEYSEAL_RELEASE_DIR"
for file in keyseal-update.json SHA256SUMS; do
  src/helper/packaging/sign-file.sh offline /Volumes/<backup drive>/keyseal-release-backup.pem \
    "draft/$file" > "$file-<login>.json"
  jq -cs '{signatures: .}' "$file"-*.json > "$file.sig"
  src/helper/packaging/verify-signatures.sh "draft/$file" "$file.sig"
done
gh workflow run release.yml --repo somus/keyseal --ref main -f tag=helper-v1.4.0 \
  -f signatures="$(cat keyseal-update.json.sig)" -f checksum_signatures="$(cat SHA256SUMS.sig)"
```

### Manifest expiry

`make-manifest.sh` sets the manifest's `expires` 180 days after the tagged
commit; the rule is in `spec/protocol-v1.md` section 13. Each helper
release renews it; nothing else does. Once it passes, helpers refuse the
manifest, write why to `keyseal.log` (and `keyseal update` prints it), keep
working, and stop updating. A patch release restores updates. Release a
recent commit and publish within the 180 days: `sign-release.sh` prints the
manifest, `expires` included, before it signs, and the publish run's
`keyseal update verify` fails on an expired manifest.

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

- Linux, with `helper/packaging/linux/build-in-container.sh`, which
  installs the packages, the pinned rustup-init and the toolchain and runs
  `build-release.sh`, in the container image the `build-linux` job of
  `.github/workflows/release.yml` names. For arm64, use `--platform
  linux/arm64` and `linux-arm64`; a Docker that won't pull the arm64 image
  by the index digest takes the arm64 digest in `sign-release.sh`. On an
  x86_64 Linux machine, arm64 runs under QEMU user emulation once
  `qemu-user-static` and `binfmt-support` are installed. A tag made before
  the script existed doesn't hold it; `sign-release.sh --verify-only`
  rebuilds such a tag with its own checkout's copy.

  ```sh
  image="$(awk '$1 == "container:" { print $2 }' .github/workflows/release.yml)"
  docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src "$image" \
    helper/packaging/linux/build-in-container.sh linux-x64 /src/dist-repro
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
with yours using `helper/packaging/macos/compare-bundle.sh`, as
`sign-release.sh` does.

### Third-party notices

The helper statically links crates whose licences ask for their notices to
go with the binary, so every package holds `THIRD-PARTY-NOTICES.txt`: the
Windows zip beside `keyseal.exe`, the macOS app in `Contents/Resources`,
the Linux tarball beside `keyseal`, and the deb and the AppImage under
`usr/share/doc/keyseal`.
The release run's `notices` job makes it once, with cargo-about 0.9.3 from
`Cargo.lock`, offline, so the same commit gives the same file anywhere.
`sign-release.sh` makes it again from the tag and compares. To make it yourself,
with `cargo-about` 0.9.3 on the `PATH`:

```sh
helper/packaging/third-party-notices.sh /tmp/THIRD-PARTY-NOTICES.txt
```

`helper/packaging/about.toml` lists the licences accepted for every
crate, all permissive, and the few accepted for one crate only, with the
reason. A dependency under any other licence fails the release run's
`notices` job; review its licence before accepting it there.

### Checking build provenance

The draft run attests every asset it builds
([Build provenance](code-signing-policy.md#build-provenance) says what that
proves and what it doesn't). Anyone can check a downloaded file with the
GitHub CLI:

```sh
gh attestation verify keyseal-helper-1.4.0-linux-x64.AppImage --repo somus/keyseal \
  --signer-workflow somus/keyseal/.github/workflows/release.yml \
  --source-ref refs/tags/helper-v1.4.0
```

### Toolchain upkeep

- Bump `helper/rust-toolchain.toml` in its own commit; CI and the release
  builds install the toolchain from it, and the next release records the
  new version in `BUILDINFO`.
- The macOS jobs pin Xcode with `DEVELOPER_DIR` in
  `.github/workflows/release.yml`; change it when the runner image drops
  that Xcode.
- Linux builds run in the `ubuntu:22.04` container, so the binary needs
  glibc 2.35 or later. `helper/packaging/linux/build-in-container.sh`
  installs GPUI's build packages there, written out to match
  `helper/linux-build-packages.txt`, the list CI and the Boat snapshot
  install from; change both together.
- The AppImage is built with appimagetool and runtime versions pinned by
  SHA-256 in the workflow, and `build-appimage.sh` fails unless the
  AppImage starts with that runtime.
- cargo-about is pinned by version and SHA-256 in the `notices` job of
  `.github/workflows/release.yml` (`.sha256` beside each archive on its
  GitHub release). `sign-release.sh` makes the notices again with the
  cargo-about on your `PATH` and requires the same bytes, so install the
  new version on the Mac too, and update the version named in this
  document and in the comments of `third-party-notices.sh` and
  `sign-release.sh`.
- Every action in `release.yml` is pinned by commit SHA with its version in
  a comment, the `ubuntu:22.04` image by digest (in `release.yml`, and per
  architecture in `sign-release.sh`), and rustup-init by version and
  SHA-256 in `build-in-container.sh`. Update a pin by resolving the new tag
  yourself (`gh api repos/actions/checkout/git/ref/tags/v7.0.1`, the
  registry's `docker-content-digest` for the image and for each
  architecture's image in its index, `rustup-init.sha256` beside the binary
  on static.rust-lang.org).
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
