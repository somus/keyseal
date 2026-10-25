#!/usr/bin/env bash
# The Linux tarball: the binary, ready for `./keyseal install`, which copies
# it to ~/.local/bin and registers keyseal:// links.
#
#   helper/packaging/linux/build-tarball.sh <linux binary> <out dir>
#
# Entries get fixed owners and SOURCE_DATE_EPOCH mtimes, so the tarball is
# as reproducible as the binary. Needs GNU tar.
set -euo pipefail

binary="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$here/../../Cargo.toml")"
name="keyseal-helper-$version-linux-x64"
: "${SOURCE_DATE_EPOCH:?}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/$name"
install -m 0755 "$binary" "$work/$name/keyseal"
mkdir -p "$out"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  -C "$work" -cf - "$name" | gzip -9n >"$out/$name.tar.gz"
echo "$out/$name.tar.gz"
