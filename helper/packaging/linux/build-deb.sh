#!/usr/bin/env bash
# The Debian package: /usr/bin/keyseal and a desktop entry that hands
# keyseal:// links to it. desktop-file-utils' dpkg trigger refreshes the
# handler cache, so no maintainer scripts are needed; it is recommended,
# since a minimal system may not have it.
#
# Depends lists the binary's NEEDED libraries (readelf -d) and the ones
# GPUI opens with dlopen to show a window: libvulkan.so.1 and, in a Wayland
# session, libwayland-client.so.0. check-deb.sh checks both lists on a
# clean system. A Vulkan driver is recommended, since a desktop has one.
#
#   helper/packaging/linux/build-deb.sh <linux binary> <out dir>
set -euo pipefail

binary="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$here/../../Cargo.toml")"
: "${SOURCE_DATE_EPOCH:?}"
# build-release.sh names the binary for its platform, linux-x64 or linux-arm64.
case "$binary" in
  *-linux-x64) deb_arch=amd64 ;;
  *-linux-arm64) deb_arch=arm64 ;;
  *)
    echo "$binary isn't a linux-x64 or linux-arm64 build." >&2
    exit 2
    ;;
esac

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
install -Dm 0755 "$binary" "$root/usr/bin/keyseal"
install -Dm 0644 "$here/keyseal.desktop" "$root/usr/share/applications/keyseal.desktop"
install -Dm 0644 "$here/keyseal.svg" "$root/usr/share/icons/hicolor/scalable/apps/keyseal.svg"
mkdir -p "$root/DEBIAN"
cat >"$root/DEBIAN/control" <<CONTROL
Package: keyseal
Version: $version
Architecture: $deb_arch
Maintainer: KeySeal maintainers
Depends: libc6 (>= 2.35), libgcc-s1, libxcb1, libxkbcommon0, libxkbcommon-x11-0, libvulkan1, libwayland-client0
Recommends: p11-kit, desktop-file-utils, mesa-vulkan-drivers | vulkan-icd
Section: utils
Priority: optional
Description: KeySeal helper
 Signs documents with a token or smart card for websites that use KeySeal.
CONTROL
# dpkg-deb only clamps mtimes to SOURCE_DATE_EPOCH; set them outright.
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$out"
dpkg-deb --root-owner-group -Zxz --build "$root" "$out/keyseal_${version}_${deb_arch}.deb" >/dev/null
echo "$out/keyseal_${version}_${deb_arch}.deb"
