#!/usr/bin/env bash
# Writes keyseal-update.json (spec/protocol-v1.md section 13) for the update
# assets, then SHA256SUMS for every asset of the release:
#
#   helper/packaging/make-manifest.sh <version> <assets dir> [<out dir>]
#
# <assets dir> must hold every asset in `assets` below except
# keyseal-update.json; both files go to <out dir>, by default <assets dir>.
# The output is fixed bytes for the same assets (the manifest is one line
# of JSON, members in a fixed order), so anyone with the draft's assets
# produces the same files and can check what they sign.
set -euo pipefail

version="$1"
dir="$2"
out="${3:-$dir}"
hash() { sha256sum "$1" | cut -d' ' -f1; }
mac="keyseal-helper-$version-macos-universal.zip"
win="keyseal-helper-$version-windows-x64.exe"
linux="keyseal-helper-$version-linux-x64.AppImage"
# Each download under a name without the version, so a site can link to
# releases/latest/download/<name> once: copies of the versioned files.
fixed=(
  "keyseal-macos-universal.dmg=keyseal-helper-$version-macos-universal.dmg"
  "keyseal-windows-x64.zip=keyseal-helper-$version-windows-x64.zip"
  "keyseal-linux-x64.AppImage=$linux"
  "keyseal_amd64.deb=keyseal_${version}_amd64.deb"
)
# Everything the release publishes besides SHA256SUMS and the signatures.
assets=(
  BUILDINFO
  SHA256SUMS-unsigned
  "$linux"
  "keyseal-helper-$version-linux-x64.tar.gz"
  "keyseal-helper-$version-macos-universal.dmg"
  "$mac"
  "$win"
  "keyseal-helper-$version-windows-x64.zip"
  keyseal-update.json
  "keyseal_${version}_amd64.deb"
  "${fixed[@]%%=*}"
)
for pair in "${fixed[@]}"; do
  cmp "$dir/${pair%%=*}" "$dir/${pair#*=}" || {
    echo "${pair%%=*} isn't a copy of ${pair#*=}." >&2
    exit 1
  }
done

# Assigned first, so a missing asset stops the script.
mac_sha="$(hash "$dir/$mac")"
win_sha="$(hash "$dir/$win")"
linux_sha="$(hash "$dir/$linux")"
mkdir -p "$out"
jq -cn --arg version "$version" \
  --arg mac "$mac" --arg mac_sha "$mac_sha" \
  --arg win "$win" --arg win_sha "$win_sha" \
  --arg linux "$linux" --arg linux_sha "$linux_sha" \
  '{format: 1, version: $version, platforms: {
     "macos-universal": {file: $mac, sha256: $mac_sha},
     "windows-x64": {file: $win, sha256: $win_sha},
     "linux-x64": {file: $linux, sha256: $linux_sha}}}' \
  >"$out/keyseal-update.json"

for asset in "${assets[@]}"; do
  if [ "$asset" = keyseal-update.json ]; then
    file="$out/$asset"
  else
    file="$dir/$asset"
  fi
  sum="$(hash "$file")"
  printf '%s  %s\n' "$sum" "$asset"
done >"$out/SHA256SUMS"
echo "$out/keyseal-update.json"
echo "$out/SHA256SUMS"
