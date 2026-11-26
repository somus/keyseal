# Packaging

The scripts that build, package, check and sign a helper release. The release workflow (`.github/workflows/release.yml`) runs the build and package scripts; the release procedure is in [docs/releasing.md](../../docs/releasing.md), and the rules it follows in [docs/code-signing-policy.md](../../docs/code-signing-policy.md). Each script's header says how to run it.

## Scripts

Build:

- `build-release.sh`: the unsigned release binary for one platform, reproducibly, with `BUILDINFO`; for macOS also the x86_64 token worker.
- `linux/build-in-container.sh`: the Linux release build inside the pinned Ubuntu 22.04 container, its packages and toolchain first, for the release run and the maintainers' rebuild.
- `third-party-notices.sh`: `THIRD-PARTY-NOTICES.txt` with cargo-about, from `about.toml` and `third-party-notices.hbs`.

Package:

- `macos/build-dmg.sh`: `KeySeal.app`, its update zip and the disk image, signed with a Developer ID or ad hoc.
- `linux/build-tarball.sh`, `linux/build-deb.sh` and `linux/build-appimage.sh`: the tarball, the deb and the AppImage.
- `make-manifest.sh`: `keyseal-update.json` and `SHA256SUMS` for a release's assets.
- The Windows zip is made in `release.yml`: `keyseal.exe`, `windows/install.cmd` and `THIRD-PARTY-NOTICES.txt`.
- `windows/build-msix.ps1`: the unsigned MSIX package for the Microsoft Store (see below).

Check:

- `check-release-commit.sh`: the commit being released is on `main` and pins `main`'s keys and threshold.
- `macos/compare-bundle.sh`: the app in a macOS zip or disk image holds exactly the given unsigned executables, once their signatures are removed.
- `linux/check-deb.sh`: the deb installs from its dependencies alone on a clean system and KeySeal starts.
- `verify-signatures.sh`: a file's signatures meet `THRESHOLD` of the pinned `RELEASE_KEYS`.

Sign:

- `new-key.sh`: makes a release or catalogue key and prints the public half to pin.
- `sign-file.sh`: signs a file with such a key.
- `macos/notarize.sh`: notarizes and staples the app or disk image.
- `sign-release.sh`: checks a draft release, signs it and publishes it, on a maintainer's Mac.
- `release-common.sh`: what `sign-release.sh` and `scripts/release.sh` share, the preflight for the rebuild and Bitwarden and the notification, sourced by both.

## Package managers

`package-managers.sh <version> <out dir>` writes the winget manifests (`KeySeal.KeySeal`), the Chocolatey package (`keyseal`) and the AUR `PKGBUILD` and `.SRCINFO` (`keyseal-bin`) for a published release, from its assets and its signature-checked `SHA256SUMS`. winget and Chocolatey run the zip's `keyseal.exe install`, so they install per user, as `install.cmd` does; the AUR package installs the Linux tarball as the deb lays it out. `.github/workflows/package-managers.yml` installs and uninstalls each on Windows and Arch Linux. Submitting them is a maintainer's step: [Package managers](../../docs/releasing.md#package-managers).

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

## Windows: the Microsoft Store package

The Microsoft Store signs the packages it distributes, so a helper installed from the Store carries no SmartScreen warning and isn't blocked by Smart App Control. The release run builds the package; a maintainer uploads it to Partner Center by hand. There is no Store listing yet, and the zip stays the documented install.

- `windows/build-msix.ps1 <keyseal.exe> <THIRD-PARTY-NOTICES.txt> <version> <out-dir>` lays out `keyseal.exe`, the notices, the logos in `windows/assets/` and `windows/AppxManifest.xml` with its values filled in, then runs `makeappx pack` from the Windows SDK. It writes `keyseal-helper-<version>-windows-x64.msix`, unsigned, and runs only on Windows.
- The package is one full-trust app (`runFullTrust`, `Windows.FullTrustApplication`) running the same `keyseal.exe` as the zip, with a KeySeal entry in the Start menu that opens the settings, the `keyseal` protocol passing the link as the only argument, as the zip's registration does, and the execution alias `keyseal.exe`, so `keyseal doctor` and `keyseal list` work from a terminal.
- `TargetDeviceFamily` is `Windows.Desktop` with `MinVersion` 10.0.17763.0 (Windows 10 1809). The execution alias needs 1709 and the protocol's `Parameters` attribute 1607; 1809 is the oldest Windows 10 release Microsoft still services (LTSC 2019), and the helper supports Windows 10 and 11. `MaxVersionTested` is 10.0.26100.0, the Windows 11 24H2 and Server 2025 build CI installs it on.
- The logos are made from `brand/keyseal-icon-windows.svg` by `scripts/make-icons.sh`, at 44, 150 and 50 pixels (`Square44x44Logo`, `Square150x150Logo`, `StoreLogo`).

### Package identity

`windows/identity.psd1` holds the package's `Name`, `Publisher` and `PublisherDisplayName`. It holds test values (`KeySeal.Dev`, `CN=KeySeal Dev`) until a maintainer reserves the name in Partner Center; then they replace the three values with the ones on the app's Product identity page, and that is the only change needed.

### Version

Store packages have four-part versions whose first part isn't 0 and whose last is 0, so 0.6.1 can't be used as it is. `build-msix.ps1` maps `major.minor.patch` to `(major+1).minor.patch.0`, so helper 0.6.1 is package 1.6.1.0. The mapping is made on one line of that script. A prerelease suffix is dropped, so a release candidate and its release get the same package version; upload only releases.

### What changes inside a package

The helper finds out at run time whether it runs from a package (`install::store_package`, from `GetCurrentPackageFamilyName`). The same exe serves both installs. In a package:

- It never downloads, stages or announces an update of itself, and `keyseal update` says the Microsoft Store keeps it up to date. The driver catalogue still refreshes after a job, daily, as in the zip install.
- `keyseal install` and `keyseal uninstall` decline and exit non-zero: the package registers the protocol and the Start menu entry, and the Store installs and removes it. Registry writes under HKCU would go to the package's private hive anyway.
- Windows keeps files the helper writes under `%APPDATA%` in `%LOCALAPPDATA%\Packages\<package family name>\LocalCache\Roaming`, so the trust store and `keyseal.log` are in `keyseal` there. The helper still sees them at `%APPDATA%\keyseal`, and `keyseal doctor` names the real folder.
- Vendor PKCS#11 drivers load by absolute path from outside the package, as in the zip install.

CI (`scripts/ci/windows-msix-smoke.ps1`, in the Windows leg of `checks.yml`) builds the package from its debug build, signs it with a throwaway certificate it trusts on the runner, installs it and checks the execution alias, that OpenSC's driver under `C:\Program Files` loads inside the package, that `keyseal update`, `install` and `uninstall` decline, that a `keyseal://` link opened through the shell starts the packaged helper and its log records the damaged link, and that the package uninstalls.

### Uploading a release to Partner Center

1. Download the `msix-windows-x64` artifact from the release run (Actions, the run for the `helper-v<version>` tag, Artifacts). It isn't a release asset, isn't in `SHA256SUMS` and isn't in `keyseal-update.json`: unsigned, nobody can install it.
2. Check that `identity.psd1` at the released commit holds the Partner Center values, not the test ones, and that the package version is higher than the last one uploaded.
3. Check that the exe inside is the release exe, byte for byte. An MSIX is a zip, so in PowerShell:

   ```powershell
   Expand-Archive keyseal-helper-<version>-windows-x64.msix msix
   (Get-FileHash msix\keyseal.exe).Hash
   (Get-FileHash keyseal-helper-<version>-windows-x64.exe).Hash
   ```

   The two hashes match, and the second is the `windows-x64` line of the release's `SHA256SUMS-unsigned`.
4. Optionally run the Windows App Certification Kit from the Windows SDK on the package, as Partner Center does on upload.
5. Upload the `.msix` as the submission's package.
