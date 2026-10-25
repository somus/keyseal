#!/usr/bin/env bash
# Wraps the universal KeySeal binary in KeySeal.app, then zips it (the update
# asset) and puts it in a disk image (the download):
#
#   helper/packaging/macos/build-dmg.sh <universal binary> <out dir> [<x86_64 token worker>]
#
# The binary is the bundle executable, since the GUI needs a real app, and
# Info.plist's CFBundleURLTypes claims keyseal:// links, which arrive as an
# Apple Event. The token worker, when given, goes beside it in
# Contents/MacOS (packaging/README.md). With KEYSEAL_CODESIGN_IDENTITY set
# ("Developer ID Application: ...") the app is signed for notarization;
# with NOTARIZE=1 as well, both the app and the disk image are notarized
# and stapled (see notarize.sh).
# Without an identity everything is ad-hoc signed, for local testing.
#
# Writes <out dir>/KeySeal.app, keyseal-helper-<version>-macos-universal.zip
# and keyseal-helper-<version>-macos-universal.dmg.
set -euo pipefail

binary="$1"
out="$2"
worker="${3:-}"
here="$(cd "$(dirname "$0")" && pwd)"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$here/../../Cargo.toml")"
identity="${KEYSEAL_CODESIGN_IDENTITY:--}"
name="keyseal-helper-$version-macos-universal"
app="$out/KeySeal.app"

mkdir -p "$out"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
sed "s/@VERSION@/$version/g" "$here/Info.plist" >"$app/Contents/Info.plist"
cp "$here/PkgInfo" "$app/Contents/PkgInfo"
cp "$here/AppIcon.icns" "$app/Contents/Resources/AppIcon.icns"
install -m 0755 "$binary" "$app/Contents/MacOS/keyseal"
if [ -n "$worker" ]; then
  install -m 0755 "$worker" "$app/Contents/MacOS/keyseal-token-worker"
fi
plutil -lint "$app/Contents/Info.plist" >/dev/null

# Both executables load vendor drivers, so both get the entitlement. The
# worker is signed first, since the app's signature seals it.
sign() {
  if [ "$identity" = "-" ]; then
    codesign --force --sign - --entitlements "$here/keyseal.entitlements" "$1"
  else
    codesign --force --sign "$identity" --options runtime --timestamp \
      --entitlements "$here/keyseal.entitlements" "$1"
  fi
}
if [ -n "$worker" ]; then
  sign "$app/Contents/MacOS/keyseal-token-worker"
fi
sign "$app"
codesign --verify --deep --strict --verbose=2 "$app"
if [ "${NOTARIZE:-}" = 1 ]; then
  "$here/notarize.sh" "$app"
fi

rm -f "$out/$name.zip"
ditto -c -k --keepParent "$app" "$out/$name.zip"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
ditto "$app" "$stage/KeySeal.app"
ln -s /Applications "$stage/Applications"
rm -f "$out/$name.dmg"
hdiutil create -quiet -volname KeySeal -srcfolder "$stage" -format UDZO "$out/$name.dmg"
if [ "$identity" != "-" ]; then
  codesign --force --sign "$identity" --timestamp "$out/$name.dmg"
fi
if [ "${NOTARIZE:-}" = 1 ]; then
  "$here/notarize.sh" "$out/$name.dmg"
fi
echo "$out/$name.dmg"
