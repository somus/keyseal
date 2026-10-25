#!/usr/bin/env bash
# The Debian package: /usr/bin/keyseal and a desktop entry that hands
# keyseal:// links to it. dpkg's desktop-file-utils trigger refreshes the
# handler cache, so no maintainer scripts are needed.
#
#   helper/packaging/linux/build-deb.sh <linux binary> <out dir>
set -euo pipefail

binary="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$here/../../Cargo.toml")"
: "${SOURCE_DATE_EPOCH:?}"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
install -Dm 0755 "$binary" "$root/usr/bin/keyseal"
install -Dm 0644 "$here/keyseal.desktop" "$root/usr/share/applications/keyseal.desktop"
install -Dm 0644 "$here/keyseal.svg" "$root/usr/share/icons/hicolor/scalable/apps/keyseal.svg"
mkdir -p "$root/DEBIAN"
cat >"$root/DEBIAN/control" <<CONTROL
Package: keyseal
Version: $version
Architecture: amd64
Maintainer: KeySeal maintainers
Depends: libc6 (>= 2.35)
Recommends: p11-kit
Section: utils
Priority: optional
Description: KeySeal helper
 Signs documents with a DSC token for websites that use KeySeal.
CONTROL
# dpkg-deb only clamps mtimes to SOURCE_DATE_EPOCH; set them outright.
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out/keyseal_${version}_amd64.deb" >/dev/null
echo "$out/keyseal_${version}_amd64.deb"
