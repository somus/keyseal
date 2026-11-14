#!/usr/bin/env bash
# Prints which parts of CI a pull request's changes need, as lines for
# $GITHUB_OUTPUT: typescript, service, helper, e2e and workflows, each true
# or false. Outside a pull request, or for any file outside the components
# and docs (a workflow or a CI script among them), it prints true for all of
# them, so main and anything unexpected run every check.
#
#   PR=<number> scripts/ci/changes.sh            # files from the GitHub API
#   scripts/ci/changes.sh <files.txt             # files on stdin, one a line
#
# Needs GH_TOKEN with pull-requests: read and GITHUB_REPOSITORY with PR.
set -euo pipefail

declare -A need=([typescript]=false [service]=false [helper]=false [e2e]=false [workflows]=false)
all() {
  for key in "${!need[@]}"; do need[$key]=true; done
}

if [ -n "${GITHUB_ACTIONS:-}" ] && [ -z "${PR:-}" ]; then
  all
else
  # A rename is listed under both names, so moving a file out of a component
  # still runs that component's checks.
  if [ -n "${PR:-}" ]; then
    files="$(gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$PR/files" \
      --jq '.[] | .filename, (.previous_filename // empty)')"
  else
    files="$(cat)"
  fi
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    case "$file" in
      # Docs: nothing builds or tests them. Patterns match across slashes.
      *.md | LICENSE | docs/* | .github/ISSUE_TEMPLATE/* | .github/CODEOWNERS) ;;
      # The helper embeds catalogue.json; the catalogue's tools test it too.
      catalogue/catalogue.json) need[helper]=true need[typescript]=true need[e2e]=true ;;
      helper/*) need[helper]=true need[e2e]=true ;;
      scripts/ci/windows-install-smoke.ps1) need[helper]=true ;;
      service/*) need[service]=true need[e2e]=true ;;
      # The reference server in e2e runs on @keyseal/server.
      packages/* | examples/* | package.json | bun.lock | tsconfig.base.json)
        need[typescript]=true need[e2e]=true ;;
      catalogue/* | oxfmt.config.ts | oxlint.config.ts | scripts/ci/node-smoke.*)
        need[typescript]=true ;;
      # Workflows, scripts and anything else: every check, CodeQL's actions
      # analysis included.
      *) all ;;
    esac
  done <<<"$files"
fi

for key in typescript service helper e2e workflows; do
  echo "$key=${need[$key]}"
done
