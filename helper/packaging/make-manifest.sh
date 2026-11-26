#!/usr/bin/env bash
# Writes keyseal-update.json (spec/protocol-v1.md section 13) for the update
# assets, then SHA256SUMS for every asset of the release:
#
#   helper/packaging/make-manifest.sh [--copy] <version> <assets dir> [<out dir>]
#
# <assets dir> must hold every asset in `assets` below except
# keyseal-update.json; both files go to <out dir>, by default <assets dir>.
# --copy first makes the copies in `fixed` below in <assets dir>, as the
# release run's draft job does; without it they must be there already.
# The manifest expires `valid_days` after the committer time of the commit
# this script is checked out at, the tagged commit in a release. The output
# is fixed bytes for the same assets and the same commit (the manifest is
# one line of JSON, members in a fixed order), so anyone with the draft's
# assets and a checkout of the tag produces the same files and can check
# what they sign.
set -euo pipefail

copy=false
if [ "$1" = --copy ]; then
  copy=true
  shift
fi
version="$1"
dir="$2"
out="${3:-$dir}"
# Helpers refuse the manifest after this, so a release more than this old
# stops updates until the next one (docs/releasing.md).
valid_days=180
committed="$(git -C "$(dirname "$0")" log -1 --format=%ct)"
[[ "$committed" =~ ^[0-9]+$ ]] || { echo "No commit time from git." >&2; exit 1; }
hash() { sha256sum "$1" | cut -d' ' -f1; }
mac="keyseal-helper-$version-macos-universal.zip"
win="keyseal-helper-$version-windows-x64.exe"
linux="keyseal-helper-$version-linux-x64.AppImage"
linux_arm="keyseal-helper-$version-linux-arm64.AppImage"
# Each download under a name without the version, so a site can link to
# releases/latest/download/<name> once: copies of the versioned files.
fixed=(
  "keyseal-macos-universal.dmg=keyseal-helper-$version-macos-universal.dmg"
  "keyseal-windows-x64.zip=keyseal-helper-$version-windows-x64.zip"
  "keyseal-linux-x64.AppImage=$linux"
  "keyseal_amd64.deb=keyseal_${version}_amd64.deb"
  "keyseal-linux-arm64.AppImage=$linux_arm"
  "keyseal_arm64.deb=keyseal_${version}_arm64.deb"
)
# Everything the release publishes besides SHA256SUMS and the signatures.
assets=(
  BUILDINFO
  SHA256SUMS-unsigned
  "$linux"
  "keyseal-helper-$version-linux-x64.tar.gz"
  "$linux_arm"
  "keyseal-helper-$version-linux-arm64.tar.gz"
  "keyseal-helper-$version-macos-universal.dmg"
  "$mac"
  "$win"
  "keyseal-helper-$version-windows-x64.zip"
  keyseal-update.json
  "keyseal_${version}_amd64.deb"
  "keyseal_${version}_arm64.deb"
  # The apt repository (linux/make-apt-repo.sh); its InRelease is added at
  # publish, like the signatures.
  Packages
  Release
  "${fixed[@]%%=*}"
)
for pair in "${fixed[@]}"; do
  if $copy; then
    cp "$dir/${pair#*=}" "$dir/${pair%%=*}"
  fi
  cmp "$dir/${pair%%=*}" "$dir/${pair#*=}" || {
    echo "${pair%%=*} isn't a copy of ${pair#*=}." >&2
    exit 1
  }
done

# Assigned first, so a missing asset stops the script.
mac_sha="$(hash "$dir/$mac")"
win_sha="$(hash "$dir/$win")"
linux_sha="$(hash "$dir/$linux")"
linux_arm_sha="$(hash "$dir/$linux_arm")"
mkdir -p "$out"
jq -cn --arg version "$version" \
  --argjson expires "$((committed + valid_days * 24 * 60 * 60))" \
  --arg mac "$mac" --arg mac_sha "$mac_sha" \
  --arg win "$win" --arg win_sha "$win_sha" \
  --arg linux "$linux" --arg linux_sha "$linux_sha" \
  --arg linux_arm "$linux_arm" --arg linux_arm_sha "$linux_arm_sha" \
  '{format: 1, version: $version, expires: ($expires | todate), platforms: {
     "macos-universal": {file: $mac, sha256: $mac_sha},
     "windows-x64": {file: $win, sha256: $win_sha},
     "linux-x64": {file: $linux, sha256: $linux_sha},
     "linux-arm64": {file: $linux_arm, sha256: $linux_arm_sha}}}' \
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
