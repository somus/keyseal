#!/usr/bin/env bash
# Builds and packs @keyseal/server and @keyseal/browser, installs the
# tarballs into an empty project and runs node-smoke.mjs there with Node, so
# it sees the packages as a consumer does: through their exports, from dist.
#
#   scripts/ci/node-smoke.sh
#
# Needs bun, node and npm; run `bun install` first.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for package in server browser; do
  (cd "$root/packages/$package" && bun run build && npm pack --pack-destination "$work")
done
cd "$work"
echo '{"private": true, "type": "module"}' >package.json
npm install --no-audit --no-fund ./keyseal-server-*.tgz ./keyseal-browser-*.tgz
cp "$root/scripts/ci/node-smoke.mjs" .
node node-smoke.mjs
