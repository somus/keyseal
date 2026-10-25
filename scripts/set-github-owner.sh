#!/usr/bin/env bash
# Replaces the OWNER placeholder in every github.com/OWNER/keyseal URL with the
# GitHub account or organisation that hosts the repository:
#
#   scripts/set-github-owner.sh <owner>
#
# The helper's release and catalogue URLs, the package manifests and the
# docs all name the repository this way. The release and catalogue signing
# keys are separate placeholders; see docs/releasing.md.
set -euo pipefail

owner="${1:-}"
if [[ ! "$owner" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]; then
  echo "usage: $0 <github owner>" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"
files=$(git grep -l 'github\.com/OWNER/keyseal' -- ':!scripts/set-github-owner.sh' || true)
if [ -z "$files" ]; then
  echo "No github.com/OWNER/keyseal URLs left." >&2
  exit 1
fi
for file in $files; do
  perl -pi -e "s{github\.com/OWNER/keyseal}{github.com/$owner/keyseal}g" "$file"
  echo "$file"
done
