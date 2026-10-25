# Code signing policy

This policy covers everything KeySeal signs for users: the helper's update
manifest, the macOS app, and, once SignPath Foundation accepts the project,
the Windows executable. The driver catalogue has its own single-maintainer
key and is outside this policy.

## What is signed, and by whom

| Artifact | Signature | Who signs | Where the key lives |
| --- | --- | --- | --- |
| `keyseal-update.json` | Ed25519, threshold of pinned keys | Maintainers | Each maintainer's YubiKeys |
| `SHA256SUMS` | Ed25519, the same keys and threshold | Maintainers | Each maintainer's YubiKeys |
| macOS `KeySeal.app` (with the token worker inside) and disk image | Apple Developer ID, notarized | The release workflow | Apple certificate in the `release-macos` GitHub environment |
| Windows `keyseal.exe` | Authenticode via SignPath Foundation (after release one) | SignPath, on a maintainer's approval | SignPath's HSM |
| Linux binaries, tarball, deb, AppImage | none in release one | | |

Every published asset is listed with its SHA-256 in the release's signed
`SHA256SUMS` (signatures in `SHA256SUMS.sig`), and the update assets also
in the signed `keyseal-update.json`. The release workflow publishes only when
both carry enough signatures and every asset matches `SHA256SUMS`.

## Who may sign

Maintainers are listed in the table below. Only they hold release keys, and
only they may approve the `release` and `release-macos` environments or
SignPath signing requests. Adding or removing a maintainer is a reviewed
change to this file and, for release keys, to `RELEASE_KEYS` in
`helper/crates/keyseal-core/src/update.rs`.

| Maintainer | Key | keyId (SHA-256 of the raw public key) |
| --- | --- | --- |
| _to be filled when the first keys are made_ | daily YubiKey | |
| | backup YubiKey | |

## Key custody

- Release keys are Ed25519 keys generated on YubiKeys (firmware 5.7 or
  later, PIV slot 9c) and are never exported. Cloud KMSs lack Ed25519, so
  there is no cloud copy.
- Each maintainer has two YubiKeys, both pinned: a daily key and a backup
  kept in a separate place. Losing one key is not an emergency.
- The PIV PIN and PUK are changed from their defaults before a key is
  pinned. The YubiKey is plugged in only to sign.
- CI never holds a release key. The Apple Developer ID certificate and App
  Store Connect API key are GitHub environment secrets usable only by the
  release workflow after a maintainer approves the run.

## Threshold

The helper accepts a manifest only when signatures from `THRESHOLD`
distinct pinned keys verify (spec section 13). The release workflow holds
`SHA256SUMS` to the same rule (`helper/packaging/verify-signatures.sh`).

- Today there is one maintainer, so the threshold is 1 of N, N being that
  maintainer's two keys.
- When a second maintainer exists, the threshold becomes 2 of N in the
  same release that pins their keys. From then on no single maintainer, and
  no single stolen YubiKey, can ship an update.

## Which commits are released

The release workflow releases only a commit on `main`, and only when its
`RELEASE_KEYS`, `THRESHOLD` and `CATALOGUE_KEYS` equal those on `main`
(`helper/packaging/check-release-commit.sh`), so a tag on an unreviewed
commit can't bring keys of its own. `helper-v*` tags are protected
(`docs/releasing.md`).

## Before signing: reproducibility

A maintainer signs a manifest and `SHA256SUMS` only after rebuilding the
unsigned binaries from the tagged source with
`helper/packaging/build-release.sh`, getting the same SHA-256 as the
release's `SHA256SUMS-unsigned`, and checking that every asset holds those
binaries (procedure in `helper/packaging/sign-manifest.md`). The macOS zip
and disk image are signed and notarized and can't be rebuilt bit for bit,
so for them the maintainer runs `helper/packaging/macos/compare-bundle.sh`,
which requires the app's executables to equal the rebuilt ones once their
code signatures are removed, and checks the Developer ID signature and
notarization. When Windows signing starts, the SignPath request is
submitted only after the same check passes for the unsigned exe.

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

If the Apple certificate or API key leaks, revoke it in the Apple Developer
account, replace the environment secrets, and re-release. If SignPath
reports a problem with a signed binary, follow SignPath Foundation's
instructions and publish a fixed release.
