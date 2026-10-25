#!/usr/bin/env bash
# Creates a SoftHSM token for end-to-end runs, the way the helper's SoftHSM
# test does, with keys whose certificates a throwaway CA issued:
#
#   scripts/ci/softhsm-token.sh <dir> <libsofthsm2 path>
#
# Writes <dir>/softhsm2.conf (export it as SOFTHSM2_CONF), the token in
# <dir>/tokens, the CA certificate alone in <dir>/roots/ca.pem (for the
# service's SIGNING_TRUST_ROOTS_DIR) and <name>.der for rsa, p256 and p384.
# The token's user PIN is 1234. Needs openssl, softhsm2-util and pkcs11-tool.
set -euo pipefail

dir="$1"
module="$2"
pin=1234

mkdir -p "$dir/tokens" "$dir/roots"
export SOFTHSM2_CONF="$dir/softhsm2.conf"
printf 'directories.tokendir = %s\n' "$dir/tokens" >"$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label keyseal-e2e --pin "$pin" --so-pin 5678 >/dev/null

cd "$dir"
openssl req -x509 -nodes -days 2 -subj "/C=IN/CN=keyseal e2e CA" \
  -newkey rsa:2048 -keyout ca.key \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out roots/ca.pem 2>/dev/null
openssl x509 -in roots/ca.pem -outform DER -out ca.der

cat >leaf.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
EOF

# name, id, then the -newkey arguments.
issue() {
  local name="$1" id="$2"
  shift 2
  openssl req -new -nodes -subj "/C=IN/CN=keyseal e2e $name" "$@" \
    -keyout "$name.pem" -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA roots/ca.pem -CAkey ca.key \
    -set_serial "0x$(openssl rand -hex 8)" -days 2 -extfile leaf.ext \
    -outform DER -out "$name.der" 2>/dev/null
  openssl pkey -in "$name.pem" -outform DER -out "$name.key"
  write "$name.der" cert "$id" "$name"
  write "$name.key" privkey "$id" "$name" --usage-sign
}

write() {
  local file="$1" type="$2" id="$3" label="$4"
  shift 4
  pkcs11-tool --module "$module" --login --pin "$pin" \
    --write-object "$file" --type "$type" --id "$id" --label "$label" "$@" >/dev/null
}

issue rsa 01 -newkey rsa:2048
issue p256 02 -newkey ec -pkeyopt ec_paramgen_curve:P-256
issue p384 03 -newkey ec -pkeyopt ec_paramgen_curve:P-384
write ca.der cert 09 ca
