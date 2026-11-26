#!/usr/bin/env bash
# Makes an OpenPGP key for the apt repository on the helper's releases and
# adds its public half to an apt keyring (docs/code-signing-policy.md, The
# apt repository key):
#
#   helper/packaging/new-apt-key.sh bitwarden "<item name>" <keyring.asc>
#   helper/packaging/new-apt-key.sh offline <file.asc> <keyring.asc>
#
# The key is an Ed25519 signing key (a version 4 key, which every apt
# verifier reads) that doesn't expire. <keyring.asc> is the armored keyring
# the deb installs, helper/packaging/linux/keyseal-archive-keyring.asc;
# keys already in it stay, so it can hold a primary and a backup key.
#
# bitwarden stores the private key as a secure note in your vault, with a
# random passphrase in the item's hidden field "passphrase"; unlock it
# first (export BW_SESSION="$(bw unlock --raw)"). offline writes it to
# <file.asc> encrypted with a passphrase you type, for a backup kept off
# this machine. Either way the key is made with its passphrase in a
# throwaway GnuPG home that is deleted, its agent stopped, when the script
# exits, so only the encrypted key is ever written to disk. Needs GnuPG 2.2
# or later, OpenSSL and jq, and bw for bitwarden.
set -euo pipefail

usage() {
  echo "usage: $0 bitwarden <item name> <keyring.asc> | offline <file.asc> <keyring.asc>" >&2
  exit 2
}
[ "$#" -eq 3 ] || usage
where="$1"
name="$2"
keyring="$3"

case "$(gpg --version | head -1)" in
  "gpg (GnuPG) 2."[2-9]* | "gpg (GnuPG) 2."[1-9][0-9]*) ;;
  *) echo "Needs GnuPG 2.2 or later; $(gpg --version | head -1) is first on the PATH." >&2; exit 1 ;;
esac

case "$where" in
  bitwarden)
    [ "$(bw status | jq -r .status)" = unlocked ] \
      || { echo 'Unlock Bitwarden first: export BW_SESSION="$(bw unlock --raw)"' >&2; exit 1; }
    bw sync >/dev/null
    [ "$(bw list items --search "$name" | jq --arg n "$name" 'map(select(.name == $n)) | length')" -eq 0 ] \
      || { echo "Bitwarden already has an item named \"$name\"." >&2; exit 1; }
    pass="$(openssl rand -base64 32)" ;;
  offline)
    [ ! -e "$name" ] || { echo "$name exists; not overwriting it." >&2; exit 1; }
    read -rsp "Passphrase for $name: " pass && echo >&2
    read -rsp "Again: " again && echo >&2
    [ -n "$pass" ] && [ "$pass" = "$again" ] || { echo "The passphrases are empty or differ." >&2; exit 1; } ;;
  *) usage ;;
esac

GNUPGHOME="$(mktemp -d)"
export GNUPGHOME
trap 'gpgconf --kill all; rm -rf "$GNUPGHOME"' EXIT
# The passphrase reaches gpg through a pipe, not its arguments or a file.
with_pass() { gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 "$@" 3< <(printf '%s\n' "$pass"); }

# The keys already in the keyring first, so a keyring gpg can't read stops
# the script before it makes a key.
if [ -s "$keyring" ]; then
  gpg --batch --quiet --import <"$keyring"
fi
with_pass --quick-generate-key "KeySeal apt repository" ed25519 sign never >&2
fingerprint="$(gpg --list-secret-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')"
public="$(gpg --armor --export-options export-minimal --export "$fingerprint")"
# GnuPG 2.5 can make version 5 keys, which gpgv on Ubuntu 22.04 and sqv
# don't read.
gpg --list-packets <<<"$public" | grep -A1 '^:public key packet:' | grep -q 'version 4,' \
  || { echo "GnuPG made a key that isn't version 4." >&2; exit 1; }
# Exported as the agent holds it: encrypted with the passphrase.
secret="$(with_pass --armor --export-secret-keys "$fingerprint")"
gpg --list-packets <<<"$secret" | grep -q 'S2K' \
  || { echo "GnuPG exported the key unencrypted." >&2; exit 1; }

case "$where" in
  bitwarden)
    # The key and passphrase reach jq through pipes, not its arguments,
    # which other processes can read.
    bw get template item \
      | jq --arg name "$name" --rawfile notes <(printf '%s\n' "$secret") --rawfile pass <(printf '%s' "$pass") \
        '.type = 2 | .secureNote = {type: 0} | .name = $name | .notes = $notes | .login = null
         | .fields = [{name: "passphrase", value: $pass, type: 1}]' \
      | bw encode | bw create item >/dev/null
    echo "Stored the private key in Bitwarden as \"$name\"." >&2 ;;
  offline)
    printf '%s\n' "$secret" >"$name"
    echo "Wrote the encrypted private key to $name. Move it off this machine." >&2 ;;
esac

# The keyring the deb installs: the keys that were in it and this one, as
# one armored block.
gpg --armor --export-options export-minimal --export >"$keyring.new"
mv "$keyring.new" "$keyring"
echo "Added the public key to $keyring."
echo "fingerprint: $fingerprint"
