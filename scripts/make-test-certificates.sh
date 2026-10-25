#!/bin/sh
# Writes the test certificates @keyseal/server's tests use, and the policy
# certificate the helper's tests share. The tests run against a fake signing
# service; only the RSA, P-256 and P-384 keys are kept, as <name>-key.pem, for
# the server's own signature checks.
set -eu
out="$(dirname "$0")/../packages/server/test/fixtures"
helper_out="$(dirname "$0")/../helper/crates/keyseal-core/tests/fixtures"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

make() {
  name="$1"
  shift
  openssl genpkey "$@" -out "$work/$name.key" 2>/dev/null
  openssl req -x509 -new -key "$work/$name.key" -subj "/C=IN/O=keyseal tests/CN=Test Signer $name" \
    -not_before 20260101000000Z -not_after 20360101000000Z -out "$out/$name.pem"
}

make rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
make p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
make p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
for name in rsa p256 p384; do
  cp "$work/$name.key" "$out/$name-key.pem"
done
make secp256k1 -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1
make ed25519 -algorithm ED25519

# A certificate policy test certificate (protocol section 8.2): issued by a CA,
# with an organization that needs escaping and two CCA India class policies.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/ca.key" 2>/dev/null
openssl req -x509 -new -key "$work/ca.key" -subj "/C=IN/O=keyseal tests/CN=KeySeal Test Sub CA" \
  -not_before 20260101000000Z -not_after 20360101000000Z -out "$work/ca.pem"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/policy.key" 2>/dev/null
openssl req -new -key "$work/policy.key" -subj "/C=IN/O=Acme, Inc./CN=Test Signer policy" -out "$work/policy.csr"
openssl x509 -req -in "$work/policy.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -not_before 20260101000000Z -not_after 20360101000000Z \
  -extfile /dev/stdin -out "$out/policy.pem" 2>/dev/null <<EXT
keyUsage = critical, digitalSignature, nonRepudiation
certificatePolicies = 2.16.356.100.2.2, 2.16.356.100.2.3
EXT
openssl x509 -in "$out/policy.pem" -outform der -out "$helper_out/policy.der"

# Names as BMPString, as some CAs still encode them, for the helper's
# DirectoryString decoding (protocol section 8.2).
printf '[req]\ndistinguished_name = dn\nstring_mask = MASK:0x800\nprompt = no\n[dn]\nCN = KeySeal BMP CA\nO = Acme BMP\n' >"$work/bmp.cnf"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/bmp.key" 2>/dev/null
openssl req -x509 -new -key "$work/bmp.key" -config "$work/bmp.cnf" \
  -not_before 20260101000000Z -not_after 20360101000000Z -outform der -out "$helper_out/bmp-names.der"
