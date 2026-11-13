#!/usr/bin/env bash
# Writes THIRD-PARTY-NOTICES.txt, the licences and notices of the crates the
# helper links, which every package ships, with cargo-about 0.9.3
# (release.yml pins it):
#
#   helper/packaging/third-party-notices.sh <out file>
#
# Offline and from the lockfile, so a commit always gives the same file on
# any machine. Fails on a licence about.toml doesn't accept.
set -euo pipefail

[ "$#" -eq 1 ] || { echo "usage: $0 <out file>" >&2; exit 2; }
out="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
here="$(cd "$(dirname "$0")" && pwd)"

# In helper/, for the toolchain rust-toolchain.toml pins.
cd "$here/.."
cargo fetch --locked >/dev/null
cargo about generate --frozen --fail --workspace --config "$here/about.toml" \
  --output-file "$out" "$here/third-party-notices.hbs"
