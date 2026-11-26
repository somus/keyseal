# Code signing policy

This policy covers everything KeySeal signs for users: the helper's update
manifest, the apt repository on the helper's releases, the macOS app, and,
once a Windows signing service accepts the project, the Windows
executable. The driver catalogue has its own single-maintainer
key and is outside this policy.

## What is signed, and by whom

| Artifact | Signature | Who signs | Where the key lives |
| --- | --- | --- | --- |
| `keyseal-update.json` | Ed25519, threshold of pinned keys | Maintainers | Each maintainer's Bitwarden vault, with an offline backup key |
| `SHA256SUMS` | Ed25519, the same keys and threshold | Maintainers | The same keys |
| `InRelease`, the apt repository's signed `Release` | OpenPGP, Ed25519, any key of the keyring the deb installs | The maintainer who publishes | Bitwarden, with an offline backup key |
| macOS `KeySeal.app` (with the token worker inside) and disk image | Apple Developer ID, notarized; ad-hoc signed until the project has a Developer ID | The release workflow | Apple certificate in the `release-macos` GitHub environment |
| Windows `keyseal.exe` | none yet: SignPath Foundation declined the first application (October 2026) | | |
| Linux binaries, tarball, deb, AppImage | none (apt checks the deb against the signed `InRelease`) | | |

Every published asset is listed with its SHA-256 in the release's signed
`SHA256SUMS` (signatures in `SHA256SUMS.sig`), and the update assets also
in the signed `keyseal-update.json`. The release workflow publishes only when
both carry enough signatures and every asset matches `SHA256SUMS`.

## Team roles

Every role is held by the maintainers in the table below, and only they
can merge to `main` (the repository's ruleset requires a pull request with
every check passing).

- **Authors** (trusted committers): the maintainers. They may push branches
  and merge pull requests.
- **Reviewers**: the maintainers review every change from someone who isn't
  one before it is merged.
- **Approvers**: the maintainers approve each Windows signing request,
  once a signing service accepts the project, and the release runs, once
  the release environments have required reviewers again
  ([Release environments](#release-environments)).

Every maintainer uses multi-factor authentication on GitHub, and on the
Windows signing service once there is one.

## Privacy

The helper sends no data to the KeySeal project. It talks to the site
that opened a job, and once a day fetches the update manifest and the
driver catalogue from this repository's GitHub releases. The README's
[Privacy](../README.md#privacy) section says what it sends to the site.

## Who may sign

Maintainers are listed in the table below. Only they hold release keys,
only they may push release tags, and only they may approve Windows
signing requests (and the `release` and `release-macos` environments, once
those have required reviewers again). Adding or removing a maintainer is a reviewed
change to this file and, for release keys, to `RELEASE_KEYS` in
`helper/crates/keyseal-core/src/update.rs`.

| Maintainer | Key | keyId (SHA-256 of the raw public key) |
| --- | --- | --- |
| Somasundaram Ayyappan (@somus) | primary, in Bitwarden | `c54378c08218e18d1cfd7c305303a89acb244acf0fdd0f05baa440854c328f68` |
| | backup, offline | `76a04142473ace19b4446a2242562e7824b047f3debcf5f59698cf33859b9177` |

## Key custody

- Release keys are Ed25519 keys made with `helper/packaging/new-key.sh`.
  Each maintainer has two, both pinned: a primary kept as a secure note in
  their Bitwarden vault, and a backup encrypted with a passphrase and kept
  offline, away from the vault. Losing one key, or access to the vault, is
  not an emergency. Releases are signed with the primary; the backup is
  used only when the primary is lost.
- The unencrypted key is never written to disk: `new-key.sh` and
  `helper/packaging/sign-file.sh` pass it to OpenSSL through a pipe. The
  vault is protected by two-factor authentication.
- A software key is exposed on the machine that signs with it, and to
  anyone who gets into the vault. Moving to YubiKeys (firmware 5.7 or later,
  Ed25519 in PIV slot 9c) removes that. The move is a normal key rotation:
  a release signed by the current keys pins the YubiKey keys, and the next
  release drops the software keys.
- The apt repository key is an OpenPGP key, described under
  [The apt repository key](#the-apt-repository-key).
- CI never holds a release key. The Apple Developer ID certificate and App
  Store Connect API key are GitHub environment secrets usable only by the
  release workflow's runs for `helper-v*` tags, which only maintainers can
  push.

A maintainer makes their two release keys once, on a machine with OpenSSL
3 or later (`brew install openssl@3` on macOS, whose own `openssl` is
LibreSSL), `jq`, `xxd` and the Bitwarden CLI logged in to their vault.
`helper/packaging/sign-release.sh` signs with the Bitwarden item named
"KeySeal release key" unless `KEYSEAL_RELEASE_KEY` names another.

```sh
export BW_SESSION="$(bw unlock --raw)"
helper/packaging/new-key.sh bitwarden "KeySeal release key"
helper/packaging/new-key.sh offline /Volumes/<backup drive>/keyseal-release-backup.pem
```

Each prints the key's `keyId` and its bytes. Add the bytes to
`RELEASE_KEYS` in a reviewed pull request, with a comment naming the
maintainer and which of their keys it is, and the keyId to the table in
[Who may sign](#who-may-sign). Catalogue keys are made the same way and
pinned in `CATALOGUE_KEYS` (`catalogue/README.md`). A new or replaced key
reaches users only in a release signed by keys their helpers already
trust; helpers that install it trust the new key from then on.

### The apt repository key

The deb adds an apt source for the flat repository on the latest helper
release and installs the public keys apt checks it with,
`helper/packaging/linux/keyseal-archive-keyring.asc`
([docs/releasing.md](releasing.md#the-apt-repository)). apt can't use the
Ed25519 release keys, so `InRelease` is signed with an OpenPGP key of its
own.

- **Algorithm:** Ed25519, as a version 4 OpenPGP key, with SHA-512
  signatures. Every apt verifier in use reads it: `gpgv` on Ubuntu 22.04
  and 24.04 and Debian 12, and `sqv`, which refuses weak algorithms, on
  Debian 13 and newer Ubuntu releases (`scripts/ci/apt-upgrade.sh` checks
  each). RSA would work too, at a larger key and signature for no gain.
- **No expiry.** An expired key makes `apt update` fail for every deb user,
  and a new expiry date reaches users only in a deb they install, so an
  expiry adds a deadline without stopping a thief: a stolen key is replaced
  by a release either way. Loss is what the keys are protected against, so
  there are two, as with release keys: a primary in the maintainer's
  Bitwarden vault, and a backup encrypted with a passphrase and kept
  offline. Both are in the keyring; apt accepts `InRelease` signed by
  either.
- **Custody:** the same rule as release keys: the unencrypted key is never
  written to disk. GnuPG works only from a keyring on disk, so
  `helper/packaging/new-apt-key.sh` and `sign-apt-release.sh` use a
  throwaway GnuPG home holding only the passphrase-protected key, give
  gpg the passphrase through a pipe, and delete the home and stop its
  agent when they exit; the decrypted key exists only in that agent's
  memory. The Bitwarden item holds the encrypted key in its notes and a
  random passphrase in a hidden field; the offline backup's passphrase is
  the maintainer's own.
- **What it protects:** a deb user's machine installs from the repository
  only what `InRelease` vouches for: `Packages` by SHA-256, and through it
  each deb's SHA-256. Someone who can change the release's files, but
  doesn't hold an apt key, can't make apt install anything. It doesn't
  vouch for the release beyond that: `sign-release.sh` signs `InRelease`
  only after every check of the draft passes, as it does `SHA256SUMS`.
  The deb's first install, a download by hand, isn't covered; that is
  what the signed `SHA256SUMS` is for. And apt runs as root, so a stolen
  apt key together with control of the release's files would let someone
  install anything on every deb user's machine: the key is held as
  carefully as a release key, although no threshold applies to it.

| Maintainer | apt key | Fingerprint |
| --- | --- | --- |
| Somasundaram Ayyappan (@somus) | primary, in Bitwarden | to be added with the key |
| | backup, offline | to be added with the key |

A release must ship `main`'s keyring, as it must pin `main`'s release
keys ([Which commits are released](#which-commits-are-released)).

## Threshold

The helper accepts a manifest only when signatures from `THRESHOLD`
distinct pinned keys verify (spec section 13), and refuses one past its
signed `expires` date ([docs/releasing.md](releasing.md#manifest-expiry)
says what that means for releasing). The release workflow holds
`SHA256SUMS` to the same rule (`helper/packaging/verify-signatures.sh`).

- Today there is one maintainer, so the threshold is 1 of N, N being that
  maintainer's two keys.
- When a second maintainer exists, the threshold becomes 2 of N in the
  same release that pins their keys. From then on no single maintainer, and
  no single stolen key, can ship an update.

## Which commits are released

The release workflow releases only a commit on `main`, and only when its
`RELEASE_KEYS`, `THRESHOLD` and `CATALOGUE_KEYS`, and its apt keyring,
equal those on `main` (`helper/packaging/check-release-commit.sh`), so a
tag on an unreviewed commit can't bring keys of its own. It also needs the `checks` and `e2e`
runs for the commit's push to `main` to have passed
(`scripts/ci/ci-passed.sh`).

- A branch ruleset on `main` requires a pull request whose `checks` and
  `e2e` checks pass, and blocks force pushes and deletion.
- A tag ruleset on `helper-v*` lets only repository admins, the
  maintainers, create, update or delete release tags, and blocks force
  pushes. The workflow's own check above would refuse a tag on a commit
  off `main`, but the ruleset keeps anyone else from making or moving
  release tags at all.

## Release environments

- The `release-macos` environment, which only `helper-v*` tags can use,
  holds the macOS signing secrets (listed in
  [docs/releasing.md](releasing.md#repository-setup)) for the build run.
- The `release` environment, which only `main` can use, runs the publish
  run.

Neither environment has a required reviewer. With one maintainer, an
approval by the account that had just pushed the tag added nothing: the
branch and tag restrictions decide which runs reach the secrets, and the
publish run accepts only signatures from the pinned keys. Required
reviewers come back when a second maintainer exists.

## Build provenance

The release run attests every asset of the draft with `actions/attest`: a
Sigstore-signed statement, recorded in GitHub and Sigstore's public
transparency log, that the file was built by `.github/workflows/release.yml`
from the tagged commit. It is made in CI with the workflow's identity, needs
no maintainer key, and isn't a release signature: helpers trust only the
signed manifest, and `SHA256SUMS.sig` is what maintainers sign. The
signatures added at publish aren't attested. It lets anyone tie a
downloaded file to the run and commit that built it; the command is in
[docs/releasing.md](releasing.md#checking-build-provenance).

## Before signing: reproducibility

A maintainer signs a manifest and `SHA256SUMS` only after
`helper/packaging/sign-release.sh` passes on the draft. It requires the tagged
commit to be on `main`, to pin `main`'s keys and to be the commit the
release run built, and remakes `keyseal-update.json` and `SHA256SUMS` from
the assets, and the apt repository's `Packages` and `Release` from the
debs, whose apt source and keyring must be the tag's. Per platform it
checks:

- **Linux**: it rebuilds the binary from the tagged source with
  `helper/packaging/build-release.sh` in the pinned container, requires the
  same SHA-256 as `SHA256SUMS-unsigned`, and requires the tarball, deb and
  AppImage to hold that binary. This is the only platform rebuilt
  independently of CI, and `--skip-rebuild` skips it, leaving the Linux
  binary and packages with no independent check. By default x64 rebuilds
  in a Boat sandbox made for the run, without the maintainer's stored
  secrets, and arm64 in Docker on the maintainer's Mac; flags move the
  rebuild to Boat, to an x86_64 Linux machine over SSH or to the Mac
  ([docs/releasing.md](releasing.md#rebuild-modes)). The sandbox or host gets the
  source and the packages and returns only the binary's SHA-256, so it
  can't change what is signed, but the comparison trusts its answer: a
  rebuild on Boat or over SSH is independent of GitHub's CI, not of Boat
  or of that host. Only a rebuild in local Docker is independent of
  both.
- **Windows**: not rebuilt. The update exe and the zip's `keyseal.exe`
  must equal the unsigned exe the release run uploaded and its entry in
  `SHA256SUMS-unsigned`, so they are checked against CI's build, not an
  independent one.
- **macOS**: not rebuilt. The release run's unsigned binaries must match
  `SHA256SUMS-unsigned`, and `helper/packaging/macos/compare-bundle.sh`
  requires the app's executables in the zip and disk image to equal them
  once their code signatures are removed. It also checks the Developer ID
  signature and notarization, or that the app is ad-hoc signed. As with
  Windows, this is checked against CI's build.

Anyone can rebuild macOS and Windows by hand with the toolchains `BUILDINFO`
names and compare with `SHA256SUMS-unsigned` (`docs/releasing.md`,
Reproducing a release), but signing doesn't wait for it. When Windows
signing starts, the signing request is submitted only after the Windows
check above passes for the unsigned exe.

## Revocation

If a release key is lost, stolen or suspected compromised:

1. Tell the other maintainers at once and stop approving releases signed
   with it.
2. Make a release that removes the key from `RELEASE_KEYS` (and pins any
   replacement), signed by the remaining keys. Helpers that install it stop
   trusting the old key.
3. Until users have updated, the old key still counts for their helpers.
   With a threshold of 2, one stolen key can't ship an update on its own.
   With a threshold of 1, warn users through the integrators and the
   download page, and ask them to reinstall from a release checked against
   its signed `SHA256SUMS`.
4. Record the event and the new keyIds in this file.

If an apt repository key is lost, stolen or suspected compromised, make a
release whose keyring drops it (and adds any replacement), signed with the
other key. Users get the new keyring with that release; until then, the
old key still counts for their apt. If both keys are lost, deb users must
install a release's deb by hand, which brings the new keyring
([docs/releasing.md](releasing.md#the-apt-repository)).

If the Apple certificate or API key leaks, revoke it in the Apple Developer
account, replace the environment secrets, and re-release. If the Windows
signing service, once there is one, reports a problem with a signed
binary, follow its instructions and publish a fixed release.
