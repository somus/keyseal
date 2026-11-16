# Packaging

The scripts that build, package, check and sign a helper release. The release workflow (`.github/workflows/release.yml`) runs the build and package scripts; the release procedure is in [docs/releasing.md](../../docs/releasing.md), and the rules it follows in [docs/code-signing-policy.md](../../docs/code-signing-policy.md). Each script's header says how to run it.

## Scripts

Build:

- `build-release.sh`: the unsigned release binary for one platform, reproducibly, with `BUILDINFO`; for macOS also the x86_64 token worker.
- `third-party-notices.sh`: `THIRD-PARTY-NOTICES.txt` with cargo-about, from `about.toml` and `third-party-notices.hbs`.

Package:

- `macos/build-dmg.sh`: `KeySeal.app`, its update zip and the disk image, signed with a Developer ID or ad hoc.
- `linux/build-tarball.sh`, `linux/build-deb.sh` and `linux/build-appimage.sh`: the tarball, the deb and the AppImage.
- `make-manifest.sh`: `keyseal-update.json` and `SHA256SUMS` for a release's assets.
- The Windows zip is made in `release.yml`: `keyseal.exe`, `windows/install.cmd` and `THIRD-PARTY-NOTICES.txt`.

Check:

- `check-release-commit.sh`: the commit being released is on `main` and pins `main`'s keys and threshold.
- `macos/compare-bundle.sh`: the app in a macOS zip or disk image holds exactly the given unsigned executables, once their signatures are removed.
- `linux/check-deb.sh`: the deb installs from its dependencies alone on a clean system and KeySeal starts.
- `verify-signatures.sh`: a file's signatures meet `THRESHOLD` of the pinned `RELEASE_KEYS`.

Sign:

- `new-key.sh`: makes a release or catalogue key and prints the public half to pin.
- `sign-file.sh`: signs a file with such a key.
- `macos/notarize.sh`: notarizes and staples the app or disk image.
- `release.sh`: checks a draft release, signs it and publishes it, on a maintainer's Mac.

## macOS: the token worker

Several Indian token drivers ship only x86_64 dylibs. The universal helper runs as arm64 on Apple Silicon and can't load them, so for such a driver it starts `keyseal-token-worker`, which loads the driver under Rosetta and runs the PKCS#11 operations over JSON lines on its stdin and stdout (`crates/keyseal-core/src/worker.rs`).

The worker is built for x86_64 only. A universal worker would run its arm64 slice on Apple Silicon and fail to load the driver the same way. It goes beside the universal helper: in `Contents/MacOS/` of the app bundle, or in the same directory as `keyseal` outside a bundle. The helper looks for it only next to its own executable and refuses one that resolves, through a symlink say, to another directory.

`build-release.sh macos-universal` builds the universal helper and the x86_64 worker, and `macos/build-dmg.sh` puts the worker in the bundle. It signs the worker like the helper, with the hardened runtime and the `com.apple.security.cs.disable-library-validation` entitlement, since both load vendor driver dylibs, and it is notarized as part of the bundle.

The worker needs Rosetta 2 (`softwareupdate --install-rosetta`). Without it the helper reports that the Intel-only driver needs Rosetta. On Intel Macs the helper loads every driver itself and never starts the worker.

To check the worker under Rosetta, build it for x86_64 and run its SoftHSM test with an x86_64 libsofthsm2 of the same version as the arm64 one that initialises the token:

```bash
cargo build -p keyseal-token-worker --target x86_64-apple-darwin
KEYSEAL_SOFTHSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
  KEYSEAL_X86_64_WORKER=target/x86_64-apple-darwin/debug/keyseal-token-worker \
  KEYSEAL_X86_64_SOFTHSM_MODULE=/path/to/x86_64/libsofthsm2.so \
  cargo test -p keyseal-token-worker
```

## Windows: the per-user install

Windows ships unsigned, as a per-user install with no installer program. SignPath Foundation declined the project's first code signing application in October 2026; the project will apply again once the helper has a record of use, and `release.yml` has a marked TODO where the signing request goes ([docs/code-signing-policy.md](../../docs/code-signing-policy.md)).

- `keyseal-helper-<version>-windows-x64.zip` holds `keyseal.exe`, `install.cmd` and `THIRD-PARTY-NOTICES.txt`. The user unzips it and double-clicks `install.cmd`, which runs `keyseal.exe install`: it copies `keyseal.exe` to `%LOCALAPPDATA%\keyseal`, removes the download mark (`Zone.Identifier`) from the copy, registers `keyseal://` under `HKCU\Software\Classes\keyseal`, adds a KeySeal shortcut to the Start menu that opens the settings, and adds KeySeal to Apps (Add or remove programs) under `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\KeySeal`. SmartScreen warns once, for the unsigned download. `install.cmd` waits for a key before closing its window; `install.cmd /quiet` doesn't, for an unattended install, and exits with `keyseal.exe install`'s exit code.
- Opening `keyseal.exe` without a link, from the Start menu or Explorer, opens the settings. From a terminal it prints the usage.
- `keyseal-helper-<version>-windows-x64.exe` is the bare binary, the update asset named in `keyseal-update.json`. Installed helpers download it themselves, so it carries no download mark.
- `keyseal uninstall`, or Uninstall in Apps, removes the registration, the shortcut, the Apps entry and the install folder. The running `keyseal.exe` can't delete itself, so a hidden PowerShell waits for it to exit and then deletes the helper's own files in `%LOCALAPPDATA%\keyseal` and the folder once it is empty.
- The exe carries version information (`crates/keyseal-helper/keyseal.rc`) whose FileDescription, KeySeal, is the name browsers show when a site opens a `keyseal://` link.
