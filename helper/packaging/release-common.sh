# shellcheck shell=bash
# Sourced by scripts/release.sh and helper/packaging/sign-release.sh: their
# messages, the preflight a helper release needs, and the notification.
# The caller sets bw_session, holding it unexported.

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }
# Boat's CLI from the PATH, kept from updating itself mid-release.
run_boat() { BOAT_NO_UPDATE=1 boat "$@"; }

# What the Linux rebuild needs for the mode in $1: default, rebuild-boat,
# rebuild-local, rebuild-host or skip-rebuild.
check_rebuild() {
  case "$1" in
    default | rebuild-boat)
      command -v boat >/dev/null && run_boat status >/dev/null 2>&1 \
        || fail "the rebuild uses Boat sandboxes and needs a signed-in boat on the PATH; or pass --rebuild-local"
      ;;
  esac
  case "$1" in
    default | rebuild-local) docker info >/dev/null 2>&1 || fail "the rebuild needs Docker running on this Mac; or pass --rebuild-boat" ;;
  esac
}

# Unlocks Bitwarden into bw_session, asking for the master password, unless
# it holds a session already.
unlock_bitwarden() {
  command -v bw >/dev/null || fail "needs bw on the PATH"
  if [ -z "$bw_session" ]; then
    [ "$(bw status | jq -r .status)" != unauthenticated ] || fail "Bitwarden isn't logged in: bw login"
    bw_session="$(bw unlock --raw)" || fail "unlocking Bitwarden"
  fi
  [ "$(BW_SESSION="$bw_session" bw status | jq -r .status)" = unlocked ] || fail "Bitwarden is locked"
}

# The terminal bell and a macOS notification saying $1, for a maintainer who
# has walked away.
notify() {
  printf '\a'
  osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "KeySeal release"' -e 'end run' \
    "$1" >/dev/null 2>&1 || true
}
