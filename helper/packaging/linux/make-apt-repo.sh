#!/usr/bin/env bash
# Writes Packages and Release, the flat apt repository the debs of a helper
# release make on the release itself (keyseal.sources):
#
#   helper/packaging/linux/make-apt-repo.sh <version> <assets dir> [<out dir>]
#
# <assets dir> must hold keyseal_<version>_amd64.deb and _arm64.deb; both
# files go to <out dir>, by default <assets dir>. Packages has each deb's
# control file with its file name, size and SHA-256, and Release the size
# and SHA-256 of Packages, dated at the committer time of the commit this
# script is checked out at (the tagged commit, the SOURCE_DATE_EPOCH the
# debs are built with). The output is fixed bytes for the same debs and the
# same commit, so a maintainer remakes both from the draft before signing
# Release into InRelease (sign-apt-release.sh). Runs on Linux and macOS;
# needs ar, tar that reads xz, sha256sum and jq.
set -euo pipefail

version="$1"
dir="$2"
out="${3:-$dir}"
committed="$(git -C "$(dirname "$0")" log -1 --format=%ct)"
[[ "$committed" =~ ^[0-9]+$ ]] || { echo "No commit time from git." >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Prints the size and SHA-256 of a file.
size_sha() { printf '%s %s' "$(wc -c <"$1" | tr -d ' ')" "$(sha256sum "$1" | cut -d' ' -f1)"; }

for arch in amd64 arm64; do
  deb="keyseal_${version}_$arch.deb"
  read -r size sha <<<"$(size_sha "$dir/$deb")"
  # Through a file: tar finds the compression of a file, not of a pipe.
  ar p "$dir/$deb" control.tar.xz >"$work/control.tar.xz"
  tar -xOf "$work/control.tar.xz" ./control
  printf 'Filename: %s\nSize: %s\nSHA256: %s\n\n' "$deb" "$size" "$sha"
  rm "$work/control.tar.xz"
done >"$work/Packages"

read -r size sha <<<"$(size_sha "$work/Packages")"
{
  echo "Origin: KeySeal"
  echo "Label: KeySeal"
  LC_ALL=C jq -rn --argjson t "$committed" '"Date: " + ($t | strftime("%a, %d %b %Y %H:%M:%S UTC"))'
  echo "Architectures: amd64 arm64"
  echo "Description: KeySeal helper"
  echo "SHA256:"
  echo " $sha $size Packages"
} >"$work/Release"
mkdir -p "$out"
mv "$work/Packages" "$work/Release" "$out/"
echo "$out/Packages"
echo "$out/Release"
