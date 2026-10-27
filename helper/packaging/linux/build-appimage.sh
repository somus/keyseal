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
appimage="$out/keyseal-helper-$version-linux-x64.AppImage"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGETOOL" --no-appstream \
  --runtime-file "$APPIMAGETOOL_RUNTIME_FILE" "$appdir" "$appimage"

# The AppImage must start with the given runtime. appimagetool fills in its
# .digest_md5 section, so both copies get that section zeroed first.
read -r offset size < <(readelf -SW "$APPIMAGETOOL_RUNTIME_FILE" \
  | awk '{ for (i = 1; i < NF; i++) if ($i == ".digest_md5") print $(i + 3), $(i + 4) }')
compare="$(dirname "$appdir")"
cp "$APPIMAGETOOL_RUNTIME_FILE" "$compare/pinned"
head -c "$(wc -c <"$APPIMAGETOOL_RUNTIME_FILE")" "$appimage" >"$compare/embedded"
for copy in "$compare/pinned" "$compare/embedded"; do
  dd if=/dev/zero of="$copy" bs=1 seek=$((0x$offset)) count=$((0x$size)) conv=notrunc status=none
done
cmp "$compare/pinned" "$compare/embedded" || {
  echo "The AppImage doesn't embed $APPIMAGETOOL_RUNTIME_FILE." >&2
  exit 1
}
echo "$appimage"
