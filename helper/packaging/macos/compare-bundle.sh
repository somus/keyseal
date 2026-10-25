#!/usr/bin/env bash
# Checks that KeySeal.app in a release's macOS zip or disk image is exactly
# the executables rebuilt with build-release.sh, the entitlements, Info.plist
# and PkgInfo in this directory, and nothing else:
#
#   helper/packaging/macos/compare-bundle.sh <zip or dmg> <rebuilt dir>
#
# <rebuilt dir> is build-release.sh macos-universal's output, from the
# tagged source. The release signs each executable, which rewrites its code
# signature, and ld already signs arm64 slices ad hoc, so neither side is
# compared as is. For every slice of KeySeal and keyseal-token-worker, both
# copies get `codesign --remove-signature`, which drops LC_CODE_SIGNATURE
# and the signature at the end of __LINKEDIT but leaves __LINKEDIT's
# vmsize as the signature grew it. That one field is zeroed in both
# copies, and the rest must be identical byte for byte: every load command,
# segment and section, and __LINKEDIT up to where the signature began.
set -euo pipefail

archive="$1"
rebuilt="$2"
here="$(cd "$(dirname "$0")" && pwd)"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$here/../../Cargo.toml")"
work="$(mktemp -d)"
mount="$work/mount"
cleanup() {
  if [ -d "$mount" ]; then hdiutil detach -quiet "$mount" || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

case "$archive" in
  *.zip) ditto -x -k "$archive" "$work" ;;
  *.dmg)
    mkdir "$mount"
    hdiutil attach -quiet -readonly -nobrowse -mountpoint "$mount" "$archive"
    ditto "$mount/KeySeal.app" "$work/KeySeal.app"
    hdiutil detach -quiet "$mount"
    rmdir "$mount"
    ;;
  *)
    echo "Expected a .zip or .dmg: $archive" >&2
    exit 2
    ;;
esac
app="$work/KeySeal.app"
codesign --verify --deep --strict "$app"
# Stapling adds Contents/CodeResources, the notarization ticket.
files="$(cd "$app" && find . -mindepth 1 ! -path ./Contents/CodeResources | LC_ALL=C sort)"
expected="./Contents
./Contents/Info.plist
./Contents/MacOS
./Contents/MacOS/keyseal
./Contents/MacOS/keyseal-token-worker
./Contents/PkgInfo
./Contents/Resources
./Contents/Resources/AppIcon.icns
./Contents/_CodeSignature
./Contents/_CodeSignature/CodeResources"
if [ "$files" != "$expected" ]; then
  echo "KeySeal.app holds other files than the release puts in it:" >&2
  diff <(echo "$expected") <(echo "$files") >&2 || true
  exit 1
fi
if [ -e "$app/Contents/CodeResources" ] && [ ! -f "$app/Contents/CodeResources" ]; then
  echo "Contents/CodeResources isn't a file." >&2
  exit 1
fi
if ! sed "s/@VERSION@/$version/g" "$here/Info.plist" | cmp -s - "$app/Contents/Info.plist"; then
  echo "Contents/Info.plist differs from Info.plist for version $version." >&2
  exit 1
fi
if ! cmp -s "$here/PkgInfo" "$app/Contents/PkgInfo"; then
  echo "Contents/PkgInfo differs from PkgInfo." >&2
  exit 1
fi
if ! cmp -s "$here/AppIcon.icns" "$app/Contents/Resources/AppIcon.icns"; then
  echo "Contents/Resources/AppIcon.icns differs from AppIcon.icns." >&2
  exit 1
fi
# Both sides through plutil, so only the entitlements count, not the
# formatting or comments.
plutil -convert xml1 -o "$work/entitlements" "$here/keyseal.entitlements"
for executable in keyseal keyseal-token-worker; do
  codesign -d --entitlements - --xml "$app/Contents/MacOS/$executable" 2>/dev/null \
    | plutil -convert xml1 -o "$work/signed" -
  if ! cmp -s "$work/entitlements" "$work/signed"; then
    echo "$executable is signed with other entitlements than keyseal.entitlements:" >&2
    plutil -p "$work/signed" >&2
    exit 1
  fi
  echo "$executable has the entitlements of keyseal.entitlements."
done

# The file offset of __LINKEDIT's vmsize in a thin 64-bit Mach-O: past the
# 32-byte header and the load commands before it, then 32 bytes into
# LC_SEGMENT_64 (cmd, cmdsize, segname, vmaddr).
linkedit_vmsize() {
  otool -l "$1" | awk '
    /^Load command/ { if (found) exit; offset += size; size = 0 }
    $1 == "cmdsize" { size = $2 }
    $1 == "segname" && $2 == "__LINKEDIT" { found = 1 }
    END { if (!found) exit 1; print 32 + offset + 32 }'
}
# A slice with its code signature removed and __LINKEDIT's vmsize zeroed.
normalized() {
  local file="$1" arch="$2" copy="$3" offset
  lipo "$file" -thin "$arch" -output "$copy" 2>/dev/null || cp "$file" "$copy"
  codesign --remove-signature "$copy"
  offset="$(linkedit_vmsize "$copy")"
  printf '\0\0\0\0\0\0\0\0' | dd of="$copy" bs=1 seek="$offset" conv=notrunc 2>/dev/null
}

compare() {
  local released="$1" ours="$2" arch
  if [ "$(lipo -archs "$released")" != "$(lipo -archs "$ours")" ]; then
    echo "$(basename "$released") has architectures $(lipo -archs "$released"), the rebuild $(lipo -archs "$ours")." >&2
    return 1
  fi
  for arch in $(lipo -archs "$ours"); do
    normalized "$released" "$arch" "$work/released"
    normalized "$ours" "$arch" "$work/ours"
    if ! cmp -s "$work/released" "$work/ours"; then
      echo "$(basename "$released") ($arch) differs from the rebuild." >&2
      return 1
    fi
    echo "$(basename "$released") ($arch) matches the rebuild."
  done
}
compare "$app/Contents/MacOS/keyseal" "$rebuilt/keyseal-helper-$version-macos-universal"
compare "$app/Contents/MacOS/keyseal-token-worker" "$rebuilt/keyseal-token-worker-$version-macos-x86_64"
