#!/usr/bin/env bash
# Checks that InRelease is Release, signed by a key of the apt keyring the
# deb installs (this checkout's linux/keyseal-archive-keyring.asc unless a
# third argument names another), as apt will check it:
#
#   helper/packaging/verify-apt-release.sh <Release> <InRelease> [<keyring.asc>]
#
# Needs GnuPG 2.2 or later.
set -euo pipefail

release="$1"
inrelease="$2"
here="$(cd "$(dirname "$0")" && pwd)"
keyring="${3:-$here/linux/keyseal-archive-keyring.asc}"

home="$(mktemp -d)"
trap 'gpgconf --homedir "$home" --kill all; rm -rf "$home"' EXIT
# gpgv reads only a binary keyring, and only that one: no other key counts.
gpg --homedir "$home" --batch --quiet --dearmor --output "$home/keyring.gpg" "$keyring"
# To stdout: gpgv 2.5 doesn't write the signed text to an --output file.
if ! gpgv --homedir "$home" --quiet --keyring "$home/keyring.gpg" --output - "$inrelease" >"$home/signed" 2>"$home/log"; then
  cat "$home/log" >&2
  echo "$inrelease isn't signed by a key of $keyring." >&2
  exit 1
fi
cmp -s "$home/signed" "$release" || { echo "$inrelease doesn't hold $release." >&2; exit 1; }
echo "$inrelease holds $release, signed by a key of $keyring."
