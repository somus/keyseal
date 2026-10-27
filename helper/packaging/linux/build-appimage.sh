#!/usr/bin/env bash
# The AppImage, built with appimagetool from a hand-made AppDir:
#
#   helper/packaging/linux/build-appimage.sh <linux binary> <out dir>
#
# APPIMAGETOOL names the appimagetool-x86_64.AppImage to use and
# APPIMAGETOOL_RUNTIME_FILE the type2 runtime to embed (the release workflow
# downloads both, pinned by hash). appimagetool reads the runtime only from
# --runtime-file; without it, it downloads the newest. It runs extracted, so
# the build host needs no FUSE.
set -euo pipefail

binary="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$here/../../Cargo.toml")"
: "${APPIMAGETOOL:?}" "${APPIMAGETOOL_RUNTIME_FILE:?}"

appdir="$(mktemp -d)/keyseal.AppDir"
trap 'rm -rf "$(dirname "$appdir")"' EXIT
install -Dm 0755 "$binary" "$appdir/usr/bin/keyseal"
install -Dm 0644 "$here/keyseal.desktop" "$appdir/keyseal.desktop"
install -Dm 0644 "$here/keyseal.svg" "$appdir/keyseal.svg"
ln -s usr/bin/keyseal "$appdir/AppRun"
mkdir -p "$out"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL" --no-appstream \
  --runtime-file "$APPIMAGETOOL_RUNTIME_FILE" \
  "$appdir" "$out/keyseal-helper-$version-linux-x64.AppImage"
echo "$out/keyseal-helper-$version-linux-x64.AppImage"
