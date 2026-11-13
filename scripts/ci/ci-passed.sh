#!/usr/bin/env bash
# Checks that checks.yml and e2e.yml passed on the commit being released
# (HEAD), in their runs for its push to main, so a tag can't publish a commit
# whose tests failed or haven't finished:
#
#   scripts/ci/ci-passed.sh
#
# Needs GH_TOKEN with actions: read, and GITHUB_REPOSITORY.
set -euo pipefail

sha="$(git rev-parse HEAD)"
for workflow in checks.yml e2e.yml; do
  passed="$(gh run list --repo "$GITHUB_REPOSITORY" --workflow "$workflow" --commit "$sha" \
    --event push --branch main --status success --json databaseId --jq length)"
  [ "$passed" -gt 0 ] || {
    echo "$workflow hasn't passed on $sha on main. Once it has, re-run this job." >&2
    exit 1
  }
done
echo "checks.yml and e2e.yml passed on $sha."
