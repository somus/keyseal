#!/usr/bin/env bash
# The Chocolatey package and the AUR PKGBUILD for a published helper
# release, from its assets: nothing is built.
#
#   helper/packaging/package-managers.sh <version> <out dir>
#
# Writes under <out dir>:
#   chocolatey/keyseal/  keyseal.nuspec and tools/
#   aur/keyseal-bin/     PKGBUILD and .SRCINFO
#
# The checksums come only from the release's SHA256SUMS, once
# verify-signatures.sh has checked it against this checkout's pinned keys.
# The AUR package also takes the desktop entry and icon from the tag, so
# the tag must be in this clone (`git fetch origin tag helper-v<version>`).
# Needs curl, git, OpenSSL 3, jq and xxd. docs/releasing.md says what to
# do with the output.
set -euo pipefail

version="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
repo=somus/keyseal
tag="helper-v$version"
releases="https://github.com/$repo/releases/download/$tag"

# The metadata the two share, from README.md, LICENSE and the deb.
name=KeySeal
publisher=KeySeal
summary='Signs documents with a token or smart card for websites that use KeySeal.'
description='KeySeal lets a web application sign PDFs with a certificate on the signer'"'"'s USB token or smart card, without a browser extension or a localhost daemon. This is its desktop helper: a site opens a keyseal:// link, and the helper shows who is asking and what will be signed, takes the token PIN and signs. It works with any token that has a PKCS#11 driver, and with hardware keys in the Windows certificate store, and is built and tested first for Indian Digital Signature Certificates (DSC).'
homepage=https://somus.github.io/keyseal/
source_url="https://github.com/$repo"
license=Apache-2.0
license_url="$source_url/blob/$tag/LICENSE"
release_notes="$source_url/releases/tag/$tag"
tags=(digital-signature dsc pdf pkcs11 smart-card)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/SHA256SUMS" "$releases/SHA256SUMS"
curl -fsSL -o "$work/SHA256SUMS.sig" "$releases/SHA256SUMS.sig"
"$here/verify-signatures.sh" "$work/SHA256SUMS" "$work/SHA256SUMS.sig" >&2

checksum() {
  local sum
  sum="$(awk -v file="$1" '$2 == file { print $1 }' "$work/SHA256SUMS")"
  if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]]; then
    echo "SHA256SUMS for $tag doesn't list $1." >&2
    exit 1
  fi
  echo "$sum"
}
from_tag() {
  git -C "$here" show "$tag:helper/packaging/linux/$1" | sha256sum | cut -d' ' -f1
}

windows_zip="keyseal-helper-$version-windows-x64.zip"
windows_url="$releases/$windows_zip"
windows_sum="$(checksum "$windows_zip")"
x64_sum="$(checksum "keyseal-helper-$version-linux-x64.tar.gz")"
arm64_sum="$(checksum "keyseal-helper-$version-linux-arm64.tar.gz")"
desktop_sum="$(from_tag keyseal.desktop)"
icon_sum="$(from_tag keyseal.svg)"

# Chocolatey: the install script downloads the Windows zip and runs its
# per-user install, as install.cmd does; the uninstall runs the installed helper's own.
choco="$out/chocolatey/keyseal"
mkdir -p "$choco/tools"
cat >"$choco/keyseal.nuspec" <<XML
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>keyseal</id>
    <version>$version</version>
    <packageSourceUrl>$source_url/blob/main/helper/packaging/package-managers.sh</packageSourceUrl>
    <owners>$publisher</owners>
    <title>$name</title>
    <authors>$publisher</authors>
    <projectUrl>$homepage</projectUrl>
    <iconUrl>https://cdn.jsdelivr.net/gh/$repo@$tag/brand/keyseal-icon.svg</iconUrl>
    <licenseUrl>$license_url</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <projectSourceUrl>$source_url</projectSourceUrl>
    <docsUrl>$source_url/tree/main/docs</docsUrl>
    <bugTrackerUrl>$source_url/issues</bugTrackerUrl>
    <tags>keyseal ${tags[*]}</tags>
    <summary>$summary</summary>
    <description>$description

KeySeal installs for the user who runs choco, in %LOCALAPPDATA%\keyseal, and updates itself. Run choco as that user, elevated; as SYSTEM the install stops, since it would belong to no one who signs.</description>
    <releaseNotes>$release_notes</releaseNotes>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
XML
cat >"$choco/tools/chocolateyinstall.ps1" <<PS1
\$ErrorActionPreference = 'Stop'

# keyseal.exe install sets KeySeal up for the account that runs it, in its
# %LOCALAPPDATA% and HKCU. As SYSTEM that is an account no one signs in to.
if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
  throw 'KeySeal installs for the user who runs choco. Run it as that user, not as SYSTEM.'
}

\$toolsDir = Split-Path -Parent \$MyInvocation.MyCommand.Definition
\$packageArgs = @{
  packageName    = \$env:ChocolateyPackageName
  unzipLocation  = \$toolsDir
  url64bit       = '$windows_url'
  checksum64     = '$windows_sum'
  checksumType64 = 'sha256'
}
Install-ChocolateyZipPackage @packageArgs

# keyseal.exe is a windowed program: piping its output makes PowerShell wait.
& (Join-Path \$toolsDir 'keyseal.exe') install | Write-Host
if (\$LASTEXITCODE -ne 0) { throw "keyseal.exe install exited with \$LASTEXITCODE." }
# The helper runs from its copy in %LOCALAPPDATA%\keyseal, so Chocolatey
# needn't keep or shim the download.
Remove-Item (Join-Path \$toolsDir 'keyseal.exe'), (Join-Path \$toolsDir 'install.cmd')
PS1
cat >"$choco/tools/chocolateyuninstall.ps1" <<'PS1'
$ErrorActionPreference = 'Stop'

$exe = Join-Path $env:LOCALAPPDATA 'keyseal\keyseal.exe'
if (-not (Test-Path $exe)) {
  Write-Warning "KeySeal isn't installed for this user; $exe is missing."
  return
}
# Removes the keyseal:// registration, the shortcut and the Apps entry; the
# folder goes once the helper has exited.
& $exe uninstall | Write-Host
if ($LASTEXITCODE -ne 0) { throw "keyseal.exe uninstall exited with $LASTEXITCODE." }
PS1

# AUR: keyseal-bin from the tarballs, laid out as the deb installs KeySeal.
# Depends is the deb's list in Arch's names (linux/build-deb.sh has why),
# and hicolor-icon-theme for the icon's folders, which namcap requires.
aur="$out/aur/keyseal-bin"
mkdir -p "$aur"
raw="https://raw.githubusercontent.com/$repo/\$_tag/helper/packaging/linux"
cat >"$aur/PKGBUILD" <<PKGBUILD
# Maintainer: KeySeal maintainers <$source_url>

pkgname=keyseal-bin
pkgver=$version
pkgrel=1
pkgdesc='${summary%.}'
arch=('x86_64' 'aarch64')
url='$homepage'
license=('$license')
depends=('glibc' 'libgcc' 'libxcb' 'libxkbcommon' 'libxkbcommon-x11' 'vulkan-icd-loader' 'wayland' 'hicolor-icon-theme')
optdepends=('p11-kit: tokens registered with p11-kit'
            'vulkan-driver: the windows, on a GPU')
provides=('keyseal')
conflicts=('keyseal')
# Released stripped; makepkg's strip would only change the bytes.
options=('!strip' '!debug')
_tag="helper-v\$pkgver"
source=("keyseal.desktop::$raw/keyseal.desktop"
        "keyseal.svg::$raw/keyseal.svg")
source_x86_64=("$source_url/releases/download/\$_tag/keyseal-helper-\$pkgver-linux-x64.tar.gz")
source_aarch64=("$source_url/releases/download/\$_tag/keyseal-helper-\$pkgver-linux-arm64.tar.gz")
sha256sums=('$desktop_sum'
            '$icon_sum')
sha256sums_x86_64=('$x64_sum')
sha256sums_aarch64=('$arm64_sum')

package() {
  local platform=x64
  [[ \$CARCH == aarch64 ]] && platform=arm64
  local dir="keyseal-helper-\$pkgver-linux-\$platform"
  install -Dm755 "\$dir/keyseal" "\$pkgdir/usr/bin/keyseal"
  install -Dm644 keyseal.desktop "\$pkgdir/usr/share/applications/keyseal.desktop"
  install -Dm644 keyseal.svg "\$pkgdir/usr/share/icons/hicolor/scalable/apps/keyseal.svg"
  install -Dm644 "\$dir/THIRD-PARTY-NOTICES.txt" "\$pkgdir/usr/share/licenses/\$pkgname/THIRD-PARTY-NOTICES.txt"
}
PKGBUILD
# What `makepkg --printsrcinfo` prints for it; the CI job compares the two.
releases_tag="$source_url/releases/download/$tag"
raw_tag="https://raw.githubusercontent.com/$repo/$tag/helper/packaging/linux"
printf '%s\n' \
  'pkgbase = keyseal-bin' \
  "	pkgdesc = ${summary%.}" \
  "	pkgver = $version" \
  '	pkgrel = 1' \
  "	url = $homepage" \
  '	arch = x86_64' \
  '	arch = aarch64' \
  "	license = $license" \
  '	depends = glibc' \
  '	depends = libgcc' \
  '	depends = libxcb' \
  '	depends = libxkbcommon' \
  '	depends = libxkbcommon-x11' \
  '	depends = vulkan-icd-loader' \
  '	depends = wayland' \
  '	depends = hicolor-icon-theme' \
  '	optdepends = p11-kit: tokens registered with p11-kit' \
  '	optdepends = vulkan-driver: the windows, on a GPU' \
  '	provides = keyseal' \
  '	conflicts = keyseal' \
  '	options = !strip' \
  '	options = !debug' \
  "	source = keyseal.desktop::$raw_tag/keyseal.desktop" \
  "	source = keyseal.svg::$raw_tag/keyseal.svg" \
  "	sha256sums = $desktop_sum" \
  "	sha256sums = $icon_sum" \
  "	source_x86_64 = $releases_tag/keyseal-helper-$version-linux-x64.tar.gz" \
  "	sha256sums_x86_64 = $x64_sum" \
  "	source_aarch64 = $releases_tag/keyseal-helper-$version-linux-arm64.tar.gz" \
  "	sha256sums_aarch64 = $arm64_sum" \
  '' \
  'pkgname = keyseal-bin' >"$aur/.SRCINFO"

echo "$out"
