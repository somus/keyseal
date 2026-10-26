#!/usr/bin/env bash
# Signs the exact bytes of a file with a key made by new-key.sh and prints
# the signature entry, {"keyId": ..., "signature": ...}: the format of each
# entry in keyseal-update.json.sig and SHA256SUMS.sig, and of
# catalogue.json.sig.
#
#   helper/packaging/sign-file.sh bitwarden "<item name>" <file>
#   helper/packaging/sign-file.sh offline <key.pem> <file>
#
# The key reaches openssl through a pipe and is never written to disk
# unencrypted. Needs OpenSSL 3 or later and jq, and bw for bitwarden.
set -euo pipefail

[ "$#" -eq 3 ] || { echo "usage: $0 bitwarden <item name> <file> | offline <key.pem> <file>" >&2; exit 2; }
where="$1"
name="$2"
file="$3"

case "$(openssl version)" in
  "OpenSSL "[3-9]*) ;;
  *) echo "Needs OpenSSL 3 or later; $(openssl version) is first on the PATH." >&2; exit 1 ;;
esac

case "$where" in
  bitwarden)
    [ "$(bw status | jq -r .status)" = unlocked ] \
      || { echo 'Unlock Bitwarden first: export BW_SESSION="$(bw unlock --raw)"' >&2; exit 1; }
    bw sync >/dev/null
    key="$(bw get notes "$name")" ;;
  offline)
    read -rsp "Passphrase for $name: " pass && echo >&2
    key="$(openssl pkey -in "$name" -passin fd:3 3<<<"$pass")" ;;
  *) echo "usage: $0 bitwarden <item name> <file> | offline <key.pem> <file>" >&2; exit 2 ;;
esac

key_id="$(printf '%s\n' "$key" | openssl pkey -pubout -outform DER | tail -c 32 | openssl dgst -sha256 -r | cut -d' ' -f1)"
# PureEdDSA signs the message itself, not a digest of it.
signature="$(printf '%s\n' "$key" | openssl pkeyutl -sign -rawin -inkey /dev/stdin -in "$file" | openssl base64 -A)"
[ "$(printf '%s' "$signature" | openssl base64 -d -A | wc -c | tr -d ' ')" -eq 64 ]
jq -cn --arg keyId "$key_id" --arg signature "$signature" '{keyId: $keyId, signature: $signature}'
