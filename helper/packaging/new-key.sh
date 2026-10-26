#!/usr/bin/env bash
# Makes an Ed25519 signing key for releases or the catalogue and prints the
# public half to pin (docs/code-signing-policy.md, Key custody):
#
#   helper/packaging/new-key.sh bitwarden "<item name>"
#   helper/packaging/new-key.sh offline <file.pem>
#
# bitwarden stores the private key as a secure note in your vault; unlock it
# first (export BW_SESSION="$(bw unlock --raw)"). offline writes it to
# <file.pem> encrypted with a passphrase you type, for a backup kept off this
# machine. Either way the unencrypted key is never written to disk. Needs
# OpenSSL 3 or later, jq and xxd, and bw for bitwarden.
set -euo pipefail

usage() {
  echo "usage: $0 bitwarden <item name> | offline <file.pem>" >&2
  exit 2
}
[ "$#" -eq 2 ] || usage
where="$1"
name="$2"

case "$(openssl version)" in
  "OpenSSL "[3-9]*) ;;
  *) echo "Needs OpenSSL 3 or later; $(openssl version) is first on the PATH." >&2; exit 1 ;;
esac

case "$where" in
  bitwarden)
    [ "$(bw status | jq -r .status)" = unlocked ] \
      || { echo 'Unlock Bitwarden first: export BW_SESSION="$(bw unlock --raw)"' >&2; exit 1; }
    bw sync >/dev/null
    [ "$(bw list items --search "$name" | jq --arg n "$name" 'map(select(.name == $n)) | length')" -eq 0 ] \
      || { echo "Bitwarden already has an item named \"$name\"." >&2; exit 1; } ;;
  offline)
    [ ! -e "$name" ] || { echo "$name exists; not overwriting it." >&2; exit 1; } ;;
  *) usage ;;
esac

key="$(openssl genpkey -algorithm ed25519)"
raw="$(printf '%s\n' "$key" | openssl pkey -pubout -outform DER | tail -c 32 | xxd -p -c 32)"

case "$where" in
  bitwarden)
    bw get template item \
      | jq --arg name "$name" --arg notes "$key" \
        '.type = 2 | .secureNote = {type: 0} | .name = $name | .notes = $notes | .login = null' \
      | bw encode | bw create item >/dev/null
    echo "Stored the private key in Bitwarden as \"$name\"." >&2 ;;
  offline)
    read -rsp "Passphrase for $name: " pass && echo >&2
    read -rsp "Again: " again && echo >&2
    [ -n "$pass" ] && [ "$pass" = "$again" ] || { echo "The passphrases are empty or differ." >&2; exit 1; }
    printf '%s\n' "$key" | openssl pkey -aes-256-cbc -passout fd:3 -out "$name" 3<<<"$pass"
    echo "Wrote the encrypted private key to $name. Move it off this machine." >&2 ;;
esac

echo "keyId: $(printf '%s' "$raw" | xxd -r -p | openssl dgst -sha256 -r | cut -d' ' -f1)"
echo "bytes: [$(printf '%s' "$raw" | sed 's/../0x&, /g; s/, $//')]"
