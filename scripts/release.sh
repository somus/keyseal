#!/usr/bin/env bash
# Releases every component whose version on main isn't released yet, from a
# clean checkout whose HEAD is origin/main, once the release pull request has
# merged (docs/releasing.md):
#
#   scripts/release.sh [--dry-run] [--rebuild-boat | --rebuild-local | --rebuild-host <ssh host> | --skip-rebuild]
#
# It decides from what GitHub holds, not from what an earlier run did, so
# running it again after a failure carries on where that run stopped:
#
# - A component whose tag (helper-v, service-v, server-v or browser-v plus
#   its version) isn't on GitHub gets the tag, once checks.yml and e2e.yml
#   have passed on the commit's push to main (scripts/ci/ci-passed.sh).
# - A helper whose release is missing or still a draft goes through
#   helper/packaging/release.sh, which gets the rebuild flags and the
#   Bitwarden session, and nothing else here sees that session.
# - server-v waits for that helper release to be published and latest, since
#   a server version can require the helper released with it.
#
# Then it waits for the npm and service runs its tags started. Bitwarden is
# unlocked at the start when a helper release is due, so the only input is
# that one password. --dry-run prints the plan and changes nothing.
#
# Needs gh, jq and git, and for a helper release what
# helper/packaging/release.sh needs.
set -euo pipefail

usage() {
  echo "usage: $0 [--dry-run] [--rebuild-boat | --rebuild-local | --rebuild-host <ssh host> | --skip-rebuild]" >&2
  exit 2
}
dry_run=false
rebuild_flags=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=true ;;
    --rebuild-boat | --rebuild-local | --skip-rebuild) [ "${#rebuild_flags[@]}" -eq 0 ] || usage; rebuild_flags=("$1") ;;
    --rebuild-host) [ "${#rebuild_flags[@]}" -eq 0 ] && [ -n "${2:-}" ] || usage; rebuild_flags=("$1" "$2"); shift ;;
    *) usage ;;
  esac
  shift
done

# Held unexported, so only the commands given it below see it.
bw_session="${BW_SESSION:-}"
unset BW_SESSION

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }
outcome="The release failed; see the terminal."
# Rung on every way out, for a maintainer who has walked away.
notify() {
  $dry_run && return
  printf '\a'
  osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "KeySeal release"' -e 'end run' \
    "$outcome" >/dev/null 2>&1 || true
}
trap notify EXIT
trap 'exit 130' INT TERM

step "Preflight"
for tool in gh jq git; do
  command -v "$tool" >/dev/null || fail "needs $tool on the PATH"
done
gh auth status >/dev/null 2>&1 || fail "gh isn't signed in: gh auth login"
cd "$(git rev-parse --show-toplevel)"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
git fetch -q origin main
[ -z "$(git status --porcelain)" ] || fail "the checkout has changes; run this from a clean checkout of main"
sha="$(git rev-parse HEAD)"
[ "$sha" = "$(git rev-parse origin/main)" ] || fail "HEAD isn't origin/main; check out main and pull"

helper_version="$(awk -F'"' '/^version = /{print $2; exit}' helper/Cargo.toml)"
# Not tomllib: macOS's own python3 is older than it. service.yml refuses a
# tag that isn't the version it reads.
service_version="$(awk -F'"' '/^version = /{print $2; exit}' service/pyproject.toml)"
server_version="$(jq -r .version packages/server/package.json)"
browser_version="$(jq -r .version packages/browser/package.json)"
helper_tag="helper-v$helper_version"
service_tag="service-v$service_version"
server_tag="server-v$server_version"
browser_tag="browser-v$browser_version"

# What GitHub holds; the plan below depends on nothing else.
tag_on_remote() { [ -n "$(git ls-remote --tags origin "refs/tags/$1")" ]; }
# missing, draft or published.
release_state() {
  gh release view "$1" --repo "$repo" --json isDraft --jq 'if .isDraft then "draft" else "published" end' 2>/dev/null \
    || echo missing
}

push_now=()
held=""
helper_due=false
for tag in "$helper_tag" "$service_tag" "$browser_tag"; do
  tag_on_remote "$tag" || push_now+=("$tag")
done
if tag_on_remote "$helper_tag"; then
  helper_state="$(release_state "$helper_tag")"
else
  helper_state="no tag"
fi
[ "$helper_state" = published ] || helper_due=true
if ! tag_on_remote "$server_tag"; then
  if $helper_due; then held="$server_tag"; else push_now+=("$server_tag"); fi
fi

step "Plan for $sha"
plan_line() { printf '  %-22s %s\n' "$1" "$2"; }
for tag in "$service_tag" "$browser_tag" "$server_tag"; do
  if [ "$tag" = "$held" ]; then
    plan_line "$tag" "push once $helper_tag is published and latest"
  elif tag_on_remote "$tag"; then
    plan_line "$tag" "done (the tag is on GitHub)"
  else
    plan_line "$tag" "push the tag"
  fi
done
case "$helper_state" in
  "no tag") plan_line "$helper_tag" "push the tag, then check, sign and publish the draft" ;;
  published) plan_line "$helper_tag" "done (published)" ;;
  missing) plan_line "$helper_tag" "wait for the draft, then check, sign and publish it" ;;
  *) plan_line "$helper_tag" "check, sign and publish the draft" ;;
esac
if [ "${#push_now[@]}" -eq 0 ] && ! $helper_due; then
  outcome="Nothing to release."
  echo "$outcome"
  exit 0
fi
if $dry_run; then
  echo "Dry run: nothing changed."
  exit 0
fi

if $helper_due; then
  # Checked before anything waits, so a missing tool fails now and not an
  # hour in.
  command -v bw >/dev/null || fail "needs bw on the PATH for the helper release"
  case "${rebuild_flags[*]:-}" in
    "" | --rebuild-boat)
      command -v boat >/dev/null && BOAT_NO_UPDATE=1 boat status >/dev/null 2>&1 \
        || fail "the Linux rebuild uses Boat sandboxes and needs a signed-in boat; or pass --rebuild-local"
      ;;
  esac
  case "${rebuild_flags[*]:-}" in
    "" | --rebuild-local) docker info >/dev/null 2>&1 || fail "the Linux rebuild needs Docker running on this Mac; or pass --rebuild-boat" ;;
  esac
  if [ -z "$bw_session" ]; then
    [ "$(bw status | jq -r .status)" != unauthenticated ] || fail "Bitwarden isn't logged in: bw login"
    bw_session="$(bw unlock --raw)" || fail "unlocking Bitwarden"
  fi
  [ "$(BW_SESSION="$bw_session" bw status | jq -r .status)" = unlocked ] || fail "Bitwarden didn't unlock"
fi

# Waits for one of the run's results; the URL goes with it either way.
wait_for_run() {
  local workflow="$1" tag="$2" run waited=0
  while :; do
    run="$(gh run list --repo "$repo" --workflow "$workflow" --event push --branch "$tag" \
      --json status,conclusion,url --jq '.[0] // empty')"
    if [ -n "$run" ] && [ "$(jq -r .status <<<"$run")" = completed ]; then
      [ "$(jq -r .conclusion <<<"$run")" = success ] || { echo "$tag: $workflow failed: $(jq -r .url <<<"$run")"; return 1; }
      echo "$tag: published by $(jq -r .url <<<"$run")"
      return 0
    fi
    # A tag push starts its run within seconds.
    if [ -z "$run" ] && [ "$waited" -ge 300 ]; then
      echo "$tag: the push started no $workflow run"
      return 1
    fi
    sleep 30
    waited=$((waited + 30))
  done
}

# At most three tags in one push: GitHub starts no workflow for a push of
# more, and the plan never holds more (helper, service and browser, or
# service, browser and server).
push_tags() {
  local tag
  for tag in "$@"; do
    git tag -f "$tag" "$sha" >/dev/null
  done
  git push -q --atomic origin "${@/#/refs/tags/}"
  echo "Pushed $*."
}

if [ "${#push_now[@]}" -gt 0 ] || [ -n "$held" ]; then
  step "Waiting for checks.yml and e2e.yml on $sha"
  for workflow in checks.yml e2e.yml; do
    while :; do
      runs="$(gh run list --repo "$repo" --workflow "$workflow" --commit "$sha" --event push --branch main \
        --json status,conclusion,url)"
      jq -e 'any(.conclusion == "success")' <<<"$runs" >/dev/null && break
      jq -e 'length > 0 and all(.status == "completed")' <<<"$runs" >/dev/null \
        && fail "$workflow failed on $sha: $(jq -r '.[0].url' <<<"$runs")"
      sleep 30
    done
    echo "$workflow passed."
  done
fi

if [ "${#push_now[@]}" -gt 0 ]; then
  step "Pushing tags"
  push_tags "${push_now[@]}"
fi

if $helper_due; then
  step "Releasing $helper_tag"
  BW_SESSION="$bw_session" KEYSEAL_NO_NOTIFY=1 \
    helper/packaging/release.sh "$helper_version" ${rebuild_flags[@]+"${rebuild_flags[@]}"}
  # Not when KEYSEAL_SIGN_ONLY=1 stopped it after signing.
  [ "$(release_state "$helper_tag")" = published ] \
    && [ "$(gh api "repos/$repo/releases/latest" --jq .tag_name)" = "$helper_tag" ] \
    || fail "$helper_tag isn't the published latest release${held:+, so $held stays unpushed}"
  if [ -n "$held" ]; then
    step "Pushing $held now that $helper_tag is latest"
    push_tags "$held"
    push_now+=("$held")
  fi
fi

failed=false
summary=()
[ "$helper_due" = false ] || summary+=("$helper_tag")
step "Waiting for the npm and service runs"
for tag in ${push_now[@]+"${push_now[@]}"}; do
  case "$tag" in
    helper-v*) continue ;;
    service-v*) workflow=service.yml ;;
    *) workflow=npm.yml ;;
  esac
  if wait_for_run "$workflow" "$tag"; then summary+=("$tag"); else failed=true; fi
done
# The tag is pushed, so a run of this script counts that component as done.
! $failed || fail "re-run the failed run in Actions once its cause is fixed"

step "Released"
printf '  %s\n' "${summary[@]}"
outcome="Released ${summary[*]}."
