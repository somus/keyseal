#!/usr/bin/env bash
# End to end: the signing service image, the reference server and the
# headless helper complete sign jobs with SoftHSM RSA-2048 (PKCS#1 v1.5 and
# PSS), P-256 and P-384 keys, a batch of three documents signed in one token
# session, two enrol jobs, one of them with a certificate policy, and two
# jobs that must fail, and every signed PDF validates as intact and trusted
# and carries the reason its job asked for.
#
#   KEYSEAL_SOFTHSM_MODULE=/path/to/libsofthsm2.so scripts/ci/e2e.sh
#
# Needs docker, bun, cargo, curl, jq, openssl, softhsm2-util and pkcs11-tool.
# E2E_SERVICE_PORT and E2E_SERVER_PORT change the ports (18090 and 18787).
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
module="${KEYSEAL_SOFTHSM_MODULE:?set KEYSEAL_SOFTHSM_MODULE to the libsofthsm2 module}"
service_port="${E2E_SERVICE_PORT:-18090}"
server_port="${E2E_SERVER_PORT:-18787}"
service="http://127.0.0.1:$service_port"
origin="http://127.0.0.1:$server_port"
image=keyseal-service:e2e
container="keyseal-e2e-$$"
work="$(mktemp -d)"
server_pid=""

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- service log" >&2
    docker logs "$container" >&2 2>&1 || true
    echo "--- reference server log" >&2
    cat "$work/server.log" >&2 || true
  fi
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

step() {
  printf '\n== %s\n' "$*"
}

# Retries `$@` once a second until it succeeds, for up to `tries` seconds.
wait_for() {
  local tries="$1"
  shift
  for _ in $(seq "$tries"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for: $*" >&2
  return 1
}

step "SoftHSM token"
"$root/scripts/ci/softhsm-token.sh" "$work/token" "$module"
export SOFTHSM2_CONF="$work/token/softhsm2.conf"

step "Signing service"
docker build -t "$image" "$root/service"
service_token="$(openssl rand -base64 32)"
docker create --name "$container" -p "127.0.0.1:$service_port:8080" \
  -e SIGNING_SERVICE_TOKEN="$service_token" \
  -e SIGNING_TSA_URL=none \
  -e SIGNING_TRUST_ROOTS_DIR=/roots \
  "$image" >/dev/null
chmod 755 "$work/token/roots"
chmod 644 "$work/token/roots/ca.pem"
docker cp "$work/token/roots" "$container:/roots"
docker start "$container" >/dev/null
wait_for 60 curl -fsS "$service/health"
curl -fsS "$service/health" | jq -e '.trustRoots == 1'

# A one-page PDF without fields; the reference server adds the signature field.
docker exec "$container" /app/.venv/bin/python -c '
import io, sys
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.writer import PdfFileWriter
writer = PdfFileWriter()
writer.insert_page(generic.DictionaryObject({
    generic.NameObject("/Type"): generic.NameObject("/Page"),
    generic.NameObject("/MediaBox"): generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 595, 842)]),
    generic.NameObject("/Resources"): generic.DictionaryObject(),
}))
out = io.BytesIO()
writer.write(out)
sys.stdout.buffer.write(out.getvalue())
' >"$work/sample.pdf"
sample="$(base64 <"$work/sample.pdf" | tr -d '\n')"

step "Helper"
(cd "$root/helper" && cargo build -p keyseal-helper)
helper="${CARGO_TARGET_DIR:-$root/helper/target}/debug/keyseal"

step "Reference server"
(
  cd "$root/examples/reference-server"
  SIGNING_SERVICE_URL="$service" SIGNING_SERVICE_TOKEN="$service_token" \
    KEYSEAL_ORIGIN="$origin" PORT="$server_port" exec bun run start
) >"$work/server.log" 2>&1 &
server_pid=$!
wait_for 30 curl -fsS "$origin/.well-known/keyseal.json"

sha256() {
  openssl dgst -sha256 -r "$1" | cut -d' ' -f1
}

# POSTs the JSON `$2` to the reference server's `$1` and prints the reply.
create() {
  curl -fsS -X POST -H 'Content-Type: application/json' --data "$2" "$origin$1"
}

# Runs the headless helper on the link in the created job `$1`.
run_helper() {
  KEYSEAL_HEADLESS=1 KEYSEAL_PIN=1234 \
    KEYSEAL_HEADLESS_TRUST_ORIGIN="$origin" KEYSEAL_ALLOW_INSECURE_ORIGINS=1 \
    KEYSEAL_PKCS11_MODULE="$module" KEYSEAL_CONFIG_DIR="$work/config" \
    "$helper" run "$(jq -r .link <<<"$1")"
}

# Checks that the signed PDF `$1` validates as intact and trusted, signed
# with the certificate whose SHA-256 is `$2`, with the reason "Approved in e2e".
check_signed() {
  local report
  report="$(curl -fsS -H "Authorization: Bearer $service_token" --data-binary "@$1" "$service/validate")"
  jq --arg sha "$2" -e '
    .status == "valid"
    and (.signatures | length) == 1
    and (.signatures[0] | .intact and .coversWholeRevision and .trusted)
    and .signatures[0].sha256Fingerprint == $sha' <<<"$report" >/dev/null || {
    echo "$report" >&2
    return 1
  }
  grep -aq '/Reason (Approved in e2e)' "$1" || {
    echo "$1: the signed PDF has no /Reason" >&2
    return 1
  }
}

# Polls job `$1` until it leaves the open states, prints its status and
# checks the state is `$2`.
final_status() {
  local status state
  for _ in $(seq 30); do
    status="$(curl -fsS "$origin/jobs/$1/status")"
    state="$(jq -r .state <<<"$status")"
    case "$state" in
      completed | failed | expired) break ;;
    esac
    sleep 1
  done
  echo "$status"
  if [ "$state" != "$2" ]; then
    echo "job $1 is $state, expected $2" >&2
    return 1
  fi
}

for name in rsa rsa-pss p256 p384; do
  step "Sign with $name"
  key="${name%-pss}"
  padding=pkcs1
  if [ "$name" = rsa-pss ]; then
    padding=pss
  fi
  fingerprint="$(sha256 "$work/token/$key.der")"
  job="$(create /jobs "$(jq -n --arg pdf "$sample" --arg sha "$fingerprint" --arg title "e2e $name" --arg padding "$padding" \
    '{documents: [{pdf: $pdf, signatureDetails: {reason: "Approved in e2e", location: "CI"}}],
      title: $title, signer: "keyseal e2e", expectedCertificateSha256: $sha, rsaPadding: $padding}')")"
  run_helper "$job"
  status="$(final_status "$(jq -r .id <<<"$job")" completed)"
  jq -e '.outputs | length == 1' <<<"$status" >/dev/null
  check_signed "$root/examples/reference-server/$(jq -r '.outputs[0]' <<<"$status")" "$fingerprint"
  echo "$name: signed PDF is intact and trusted, with its reason"
done

step "Sign a batch of three documents with p256"
fingerprint="$(sha256 "$work/token/p256.der")"
job="$(create /jobs "$(jq -n --arg pdf "$sample" --arg sha "$fingerprint" \
  '{documents: [range(1; 4) | {pdf: $pdf, title: "e2e batch document \(.)",
      signatureDetails: {reason: "Approved in e2e", location: "Batch \(.)"}}],
    title: "e2e batch, 3 documents", signer: "keyseal e2e", expectedCertificateSha256: $sha}')")"
run_helper "$job"
status="$(final_status "$(jq -r .id <<<"$job")" completed)"
jq -e '.outputs | length == 3' <<<"$status" >/dev/null
for index in 0 1 2; do
  signed="$root/examples/reference-server/$(jq -r --argjson index "$index" '.outputs[$index]' <<<"$status")"
  check_signed "$signed" "$fingerprint"
  grep -aq "/Location (Batch $((index + 1)))" "$signed" || {
    echo "batch document $index is not the PDF its job asked for" >&2
    exit 1
  }
done
echo "batch: all three signed PDFs are intact and trusted, in order"

step "Enrol"
job="$(create /enrol-jobs "$(jq -n --arg sha "$(sha256 "$work/token/p256.der")" \
  '{title: "e2e enrolment", signer: "keyseal e2e", expectedCertificateSha256: $sha}')")"
run_helper "$job"
final_status "$(jq -r .id <<<"$job")" completed >/dev/null
echo "enrol job completed"

step "Enrol with a certificate policy"
job="$(create /enrol-jobs "$(jq -n --arg sha "$(sha256 "$work/token/p256.der")" \
  '{title: "e2e policy enrolment", signer: "keyseal e2e", expectedCertificateSha256: $sha,
    certificatePolicy: {issuerCommonNames: ["keyseal e2e CA"]}}')")"
run_helper "$job"
final_status "$(jq -r .id <<<"$job")" completed >/dev/null
echo "policy enrol job completed"

step "Wrong expected certificate"
# The RSA certificate's hash with its first hex digit changed: no
# certificate on the token matches, so the helper must fail the job.
right="$(sha256 "$work/token/rsa.der")"
case "$right" in
  0*) wrong="1${right#?}" ;;
  *) wrong="0${right#?}" ;;
esac
job="$(create /jobs "$(jq -n --arg pdf "$sample" --arg sha "$wrong" \
  '{documents: [{pdf: $pdf}], title: "e2e mismatch", signer: "keyseal e2e", expectedCertificateSha256: $sha}')")"
if run_helper "$job"; then
  echo "the helper signed a job for a certificate the token doesn't hold" >&2
  exit 1
fi
final_status "$(jq -r .id <<<"$job")" failed | jq -r '"failed job message: \(.message)"'

step "Unmet certificate policy"
# No certificate on the token carries the CCA India Class 3 policy OID.
job="$(create /jobs "$(jq -n --arg pdf "$sample" \
  '{documents: [{pdf: $pdf}], title: "e2e policy", signer: "keyseal e2e", certificatePolicy: {policyOids: ["2.16.356.100.2.3"]}}')")"
if run_helper "$job"; then
  echo "the helper signed a job whose certificate policy no certificate satisfies" >&2
  exit 1
fi
final_status "$(jq -r .id <<<"$job")" failed |
  jq -e --arg origin "$origin" '.message == "None of the certificates on this token are accepted by \($origin) for this job."' >/dev/null
echo "unmet policy failed the job"

step "Passed"
