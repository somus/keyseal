#!/usr/bin/env bash
# Signs a release's apt Release file with a key made by new-apt-key.sh and
# prints InRelease, the clearsigned Release apt reads:
#
#   helper/packaging/sign-apt-release.sh bitwarden "<item name>" <Release>
#   helper/packaging/sign-apt-release.sh offline <key.asc> <Release>
#
# The key, encrypted with its passphrase, goes into a throwaway GnuPG home
# that is deleted, its agent stopped, when the script exits; the passphrase
# reaches gpg through a pipe. So only the encrypted key is ever written to
# disk. Needs GnuPG 2.2 or later and jq, and bw for bitwarden.
set -euo pipefail

usage() {
  echo "usage: $0 bitwarden <item name> <Release> | offline <key.asc> <Release>" >&2
  exit 2
}
[ "$#" -eq 3 ] || usage
where="$1"
name="$2"
release="$3"
[ -f "$release" ] || { echo "No file $release." >&2; exit 1; }

case "$where" in
  bitwarden)
    [ "$(bw status | jq -r .status)" = unlocked ] \
      || { echo 'Unlock Bitwarden first: export BW_SESSION="$(bw unlock --raw)"' >&2; exit 1; }
    bw sync >/dev/null
    item="$(bw get item "$name")"
    key="$(jq -r .notes <<<"$item")"
    pass="$(jq -r '.fields[] | select(.name == "passphrase") | .value' <<<"$item")"
    unset item ;;
  offline)
    key="$(cat "$name")"
    read -rsp "Passphrase for $name: " pass && echo >&2 ;;
  *) usage ;;
esac

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill all; rm -rf "$GNUPGHOME"' EXIT
with_pass() { gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 "$@" 3< <(printf '%s\n' "$pass"); }

# Refused unless the key is encrypted, so the GnuPG home never holds it in
# the clear.
gpg --list-packets <<<"$key" | grep -q 'S2K' || { echo "$name isn't an encrypted OpenPGP key." >&2; exit 1; }
with_pass --import <<<"$key"
fingerprint="$(gpg --list-secret-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')"
# SHA-512: apt's verifiers refuse SHA-1 and accept this everywhere.
with_pass --local-user "$fingerprint" --digest-algo SHA512 --clearsign --output - "$release"
