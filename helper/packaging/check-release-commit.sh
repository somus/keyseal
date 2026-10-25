#!/usr/bin/env bash
# Checks that the commit being released (HEAD) is on main and pins the same
# release and catalogue keys and threshold as main does now, so a tag on an
# unreviewed commit can't bring its own keys:
#
#   helper/packaging/check-release-commit.sh
#
# Needs origin/main fetched (actions/checkout with fetch-depth: 0).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
git merge-base --is-ancestor HEAD origin/main || {
  echo "$(git rev-parse HEAD) is not on main; release only reviewed commits." >&2
  exit 1
}

# The declarations that decide which signatures helpers accept.
pinned() {
  awk '/^pub const (RELEASE_KEYS|THRESHOLD|CATALOGUE_KEYS):/ { p = 1 } p { print } p && (/^\];/ || /^pub const .*;[[:space:]]*$/) { p = 0 }'
}
for path in helper/crates/keyseal-core/src/update.rs helper/crates/keyseal-core/src/catalogue.rs; do
  ours="$(pinned <"$path")"
  main="$(git show "origin/main:$path" | pinned)"
  if [ -z "$ours" ] || [ "$ours" != "$main" ]; then
    echo "The pinned keys in $path differ from main's (or are missing):" >&2
    diff <(echo "$main") <(echo "$ours") >&2 || true
    exit 1
  fi
done
echo "$(git rev-parse HEAD) is on main and pins main's keys."
