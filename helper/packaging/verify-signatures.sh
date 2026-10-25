#!/usr/bin/env bash
# Checks the maintainers' signatures over a file the helper doesn't verify
# itself, SHA256SUMS, by the manifest's rule (spec/protocol-v1.md section
# 13): signatures from at least THRESHOLD distinct keys of RELEASE_KEYS, as
# pinned in this checkout's helper/crates/keyseal-core/src/update.rs.
#
#   helper/packaging/verify-signatures.sh <file> <signatures>
#
# <signatures> is {"signatures": [{"keyId": ..., "signature": ...}]}, the
# format of keyseal-update.json.sig. Needs OpenSSL 3, jq and xxd.
set -euo pipefail

file="$1"
signatures="$2"
here="$(cd "$(dirname "$0")" && pwd)"
update="$here/../crates/keyseal-core/src/update.rs"

# The keys are pinned as `xxd -i` bytes (sign-manifest.md); one line of 64
# hex digits per key. The placeholder [[0; 32]] yields none.
keys="$(awk '/^pub const RELEASE_KEYS:/ { p = 1 } p { print } p && (/^\];/ || /^pub const .*;[[:space:]]*$/) { exit }' "$update" \
  | sed 's#//.*##' | grep -oE '0x[0-9a-fA-F]{2}' | sed 's/^0x//' | tr -d '\n' | fold -w 64 | sort -u || true)"
threshold="$(sed -n 's/^pub const THRESHOLD: usize = \([0-9][0-9]*\);$/\1/p' "$update")"
if [ -z "$threshold" ] || [ "$threshold" -lt 1 ]; then
  echo "No THRESHOLD of at least 1 in $update." >&2
  exit 1
fi

# As in the helper, a keyId listed twice makes the file malformed.
jq -e '.signatures | type == "array" and (map(.keyId) | length) == (map(.keyId) | unique | length)' \
  "$signatures" >/dev/null || {
  echo "$signatures is malformed or lists a key twice." >&2
  exit 1
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
verified=0
while read -r key; do
  [ "${#key}" -eq 64 ] || continue
  id="$(printf '%s' "$key" | xxd -r -p | sha256sum | cut -d' ' -f1)"
  jq -r --arg id "$id" '.signatures[] | select(.keyId == $id) | .signature' "$signatures" >"$work/signature.b64"
  [ -s "$work/signature.b64" ] || continue
  openssl base64 -d -A -in "$work/signature.b64" -out "$work/signature.raw" || continue
  # SubjectPublicKeyInfo for a raw Ed25519 key.
  printf '302a300506032b6570032100%s' "$key" | xxd -r -p >"$work/key.der"
  if openssl pkeyutl -verify -pubin -keyform DER -inkey "$work/key.der" -rawin \
    -in "$file" -sigfile "$work/signature.raw" >/dev/null 2>&1; then
    verified=$((verified + 1))
  fi
done <<<"$keys"

if [ "$verified" -lt "$threshold" ]; then
  echo "$file has $verified of the $threshold signatures it needs." >&2
  exit 1
fi
echo "$file is signed by $verified pinned keys; $threshold needed."
