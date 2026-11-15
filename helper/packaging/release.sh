#!/usr/bin/env bash
# Checks a draft helper release, signs it and publishes it, on a
# maintainer's Mac (docs/releasing.md). scripts/release.sh runs it; it also
# runs on its own:
#
#   helper/packaging/release.sh <version> [--verify-only]
#     [--rebuild-boat | --rebuild-local | --rebuild-host <ssh host> | --skip-rebuild]
#
# 1. Downloads the draft and clones its tag, and requires the tagged commit
#    to be on main, to pin main's keys (check-release-commit.sh, this
#    checkout's copy) and to be the commit the release run built, so every
#    check runs reviewed scripts.
# 2. Checks keyseal-update.json and SHA256SUMS against the assets, the
#    Windows exe and zip against the unsigned exe the release run built, and
#    the macOS zip and disk image against its unsigned binaries
#    (compare-bundle.sh), with their Developer ID or ad-hoc signature. The
#    zip and the app must hold the third-party notices this script makes
#    from the tagged source (third-party-notices.sh).
# 3. Rebuilds the Linux binaries in the pinned container and requires each
#    to equal SHA256SUMS-unsigned and the binary in the tarball, deb and
#    AppImage (unpacked, never run). The source and the Linux packages are
#    streamed into a throwaway container, which gets no access to the work
#    directory, and only its last line, the rebuilt binary's SHA-256, is
#    compared. Both architectures rebuild at the same time. By default x64
#    runs in a Boat sandbox and arm64 in Docker on this Mac, natively on
#    Apple silicon. --rebuild-boat runs arm64 in a second sandbox too, under
#    QEMU user emulation, so the Mac needs no Docker but it takes about 40
#    minutes; --rebuild-local runs both in Docker on this Mac;
#    --rebuild-host runs both natively on an x86_64 Linux machine with
#    Docker over SSH, so nothing is written on that machine but Docker's
#    image cache; and --skip-rebuild skips it, accepting that CI built what
#    the tag holds.
# 4. Signs both files with the release key in Bitwarden
#    ($KEYSEAL_RELEASE_KEY, by default "KeySeal release key"), verifies the
#    signatures with verify-signatures.sh, starts the publish run, waits for
#    it, and requires the release to be published and latest.
#
# A missing draft is waited for: the tag's release run makes it. Bitwarden
# is unlocked once at the start unless BW_SESSION is set; either way the
# session is taken out of the environment and handed only to bw and
# sign-file.sh. The terminal bell and a notification mark the end, unless
# KEYSEAL_NO_NOTIFY=1 (scripts/release.sh notifies instead).
#
# --verify-only stops after step 3, needs no Bitwarden, and takes a published
# release as well as a draft, whose uploaded signatures it then verifies too.
#
# With a THRESHOLD above 1 each maintainer runs it with KEYSEAL_SIGN_ONLY=1
# and sends their two .json entries; whoever publishes puts every entry in
# the work directory before running it without.
#
# Needs gh, jq, git, bw, OpenSSL 3 or later, the Xcode command line tools,
# and rustup and cargo-about 0.9.3 for the notices; boat for the default
# rebuild and --rebuild-boat, Docker for the default and --rebuild-local.
# Works in $KEYSEAL_RELEASE_DIR, a directory you own (made private), or by
# default a new private one under $TMPDIR; its path must not hold a space.
set -euo pipefail

usage() {
  echo "usage: $0 <version> [--verify-only] [--rebuild-boat | --rebuild-local | --rebuild-host <ssh host> | --skip-rebuild]" >&2
  exit 2
}
version=""
verify_only=false
rebuild=""
rebuild_host=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --verify-only) verify_only=true ;;
    --rebuild-boat | --rebuild-local | --rebuild-host | --skip-rebuild)
      [ -z "$rebuild" ] || usage
      rebuild="${1#--}"
      if [ "$1" = --rebuild-host ]; then
        rebuild_host="${2:-}"
        [ -n "$rebuild_host" ] || usage
        shift
      fi
      ;;
    -*) usage ;;
    *) [ -z "$version" ] || usage; version="$1" ;;
  esac
  shift
done
rebuild="${rebuild:-default}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

# Held unexported, so no process this script starts inherits it; only bw
# and sign-file.sh get it, per command.
bw_session="${BW_SESSION:-}"
unset BW_SESSION

tag="helper-v$version"
here="$(cd "$(dirname "$0")" && pwd)"
key="${KEYSEAL_RELEASE_KEY:-KeySeal release key}"
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }
# Boat's CLI from the PATH, kept from updating itself mid-release.
run_boat() { BOAT_NO_UPDATE=1 boat "$@"; }
# Deleted on every way out of this script, and only the ones it made.
sandboxes=()
outcome="$tag: the release failed; see the terminal."
on_exit() {
  for id in ${sandboxes[@]+"${sandboxes[@]}"}; do
    run_boat delete "$id" --yes >/dev/null || echo "Couldn't delete Boat sandbox $id; delete it with: boat delete $id" >&2
  done
  # For a maintainer who has walked away.
  if [ "${KEYSEAL_NO_NOTIFY:-}" != 1 ]; then
    printf '\a'
    osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "KeySeal release"' -e 'end run' \
      "$outcome" >/dev/null 2>&1 || true
  fi
}
trap on_exit EXIT
trap 'exit 130' INT TERM

step "Preflight"
for tool in gh jq git openssl codesign ditto spctl cargo-about rustup; do
  command -v "$tool" >/dev/null || fail "needs $tool on the PATH"
done
case "$(openssl version)" in
  "OpenSSL "[3-9]*) ;;
  *) fail "needs OpenSSL 3 or later first on the PATH, not $(openssl version)" ;;
esac
gh auth status >/dev/null 2>&1 || fail "gh isn't signed in: gh auth login"
case "$rebuild" in
  default | rebuild-boat)
    command -v boat >/dev/null && run_boat status >/dev/null 2>&1 \
      || fail "the rebuild uses Boat sandboxes and needs a signed-in boat on the PATH; or pass --rebuild-local"
    ;;
esac
case "$rebuild" in
  default | rebuild-local) docker info >/dev/null 2>&1 || fail "the rebuild needs Docker running on this Mac; or pass --rebuild-boat" ;;
esac
if ! $verify_only; then
  command -v bw >/dev/null || fail "needs bw on the PATH"
  if [ -z "$bw_session" ]; then
    [ "$(bw status | jq -r .status)" != unauthenticated ] || fail "Bitwarden isn't logged in: bw login"
    bw_session="$(bw unlock --raw)" || fail "unlocking Bitwarden"
  fi
  [ "$(BW_SESSION="$bw_session" bw status | jq -r .status)" = unlocked ] || fail "Bitwarden is locked"
fi
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
signer="$(gh api user --jq .login)"

# The scripts and files in here run and get signed with the release key, so
# nobody else may write to it.
if [ -n "${KEYSEAL_RELEASE_DIR:-}" ]; then
  work="$KEYSEAL_RELEASE_DIR"
  mkdir -p "$work"
  [ -d "$work" ] && [ ! -L "$work" ] && [ -O "$work" ] \
    || fail "$work must be a directory you own, not a symlink"
  chmod 700 "$work"
else
  work="$(mktemp -d "${TMPDIR:-/tmp}/keyseal-release-$version.XXXXXX")"
fi

# The tag's release run makes the draft; wait for it rather than fail. The
# draft exists before the run has uploaded every asset, so a run still
# going is waited for even when the draft is there.
waited=0
while :; do
  run="$(gh run list --repo "$repo" --workflow release.yml --event push --branch "$tag" \
    --json status,conclusion,url --jq '.[0] // empty')"
  if [ -n "$run" ] && [ "$(jq -r .status <<<"$run")" != completed ]; then
    :
  elif is_draft="$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft 2>/dev/null)"; then
    break
  elif [ -n "$run" ]; then
    [ "$(jq -r .conclusion <<<"$run")" = success ] || fail "the release run for $tag failed: $(jq -r .url <<<"$run")"
    fail "the release run for $tag passed but made no release: $(jq -r .url <<<"$run")"
  else
    [ "$waited" -lt 600 ] || fail "$tag has no release and no release run in $repo"
  fi
  [ "$waited" -gt 0 ] || echo "Waiting for the release run of $tag to make the draft."
  sleep 30
  waited=$((waited + 30))
done
$verify_only || [ "$is_draft" = true ] || fail "$tag is not a draft release in $repo"

step "Downloading the draft and the tagged source into $work"
rm -rf "$work/draft" "$work/src" "$work/ci-unsigned" "$work/ci-windows" "$work/mine" "$work/unzipped" "$work/rebuilt" "$work"/rebuild-* "$work"/rebuilt-* "$work/THIRD-PARTY-NOTICES.txt"
gh release download "$tag" --repo "$repo" --dir "$work/draft"
# Not `clone --branch`: it would take a branch named like the tag over the tag.
git clone -q --no-checkout "https://github.com/$repo.git" "$work/src"
git -C "$work/src" checkout -q "refs/tags/$tag"
src="$work/src"
draft="$work/draft"
commit="$(git -C "$src" rev-parse HEAD)"
(cd "$src" && "$here/check-release-commit.sh")
unsigned_hash() { awk -v f="$1" '$2 == f { print $1 }' "$draft/SHA256SUMS-unsigned"; }

# The release run that built the tagged commit: its unsigned binaries, not the
# draft's own SHA256SUMS-unsigned, are what the draft's assets must hold.
# Filtered by tag and commit on GitHub's side, so older runs can't push it
# out of the page.
run="$(gh run list --repo "$repo" --workflow release.yml --event push \
  --branch "$tag" --commit "$commit" --status success \
  --json databaseId,headBranch,headSha,conclusion \
  --jq "map(select(.headBranch == \"$tag\" and .headSha == \"$commit\" and .conclusion == \"success\"))[0].databaseId")"
[ -n "$run" ] && [ "$run" != null ] || fail "no successful release run for $tag at $commit"
# Apart: both hold a BUILDINFO.
gh run download "$run" --repo "$repo" --name unsigned-macos-universal --dir "$work/ci-unsigned"
gh run download "$run" --repo "$repo" --name unsigned-windows-x64 --dir "$work/ci-windows"

step "keyseal-update.json and SHA256SUMS describe the assets"
"$src/helper/packaging/make-manifest.sh" "$version" "$draft" "$work/mine" >/dev/null
cmp "$work/mine/keyseal-update.json" "$draft/keyseal-update.json" || fail "keyseal-update.json"
cmp "$work/mine/SHA256SUMS" "$draft/SHA256SUMS" || fail "SHA256SUMS"
jq . "$draft/keyseal-update.json"

step "Third-party notices from the tagged source"
"$src/helper/packaging/third-party-notices.sh" "$work/THIRD-PARTY-NOTICES.txt" \
  || fail "making the third-party notices"
notices="$work/THIRD-PARTY-NOTICES.txt"

step "Windows"
win="$draft/keyseal-helper-$version-windows-x64"
cmp "$win.exe" "$work/ci-windows/keyseal-helper-$version-windows-x64.exe" \
  || fail "the update exe isn't the run's unsigned build"
[ "$(shasum -a 256 "$win.exe" | cut -d' ' -f1)" = "$(unsigned_hash "keyseal-helper-$version-windows-x64.exe")" ] \
  || fail "the update exe isn't in SHA256SUMS-unsigned"
[ "$(unzip -Z1 "$win.zip" | LC_ALL=C sort | tr '\n' ' ')" = "THIRD-PARTY-NOTICES.txt install.cmd keyseal.exe " ] \
  || fail "the zip holds other files"
unzip -p "$win.zip" keyseal.exe | cmp - "$win.exe" || fail "the zip's keyseal.exe"
# The Windows checkout gives install.cmd CRLF line endings.
unzip -p "$win.zip" install.cmd | tr -d '\r' | cmp - "$src/helper/packaging/windows/install.cmd" \
  || fail "the zip's install.cmd"
unzip -p "$win.zip" THIRD-PARTY-NOTICES.txt | cmp - "$notices" || fail "the zip's THIRD-PARTY-NOTICES.txt"
echo "The zip holds the update exe, install.cmd and the notices."

step "macOS"
for file in "keyseal-helper-$version-macos-universal" "keyseal-token-worker-$version-macos-x86_64"; do
  [ "$(shasum -a 256 "$work/ci-unsigned/$file" | cut -d' ' -f1)" = "$(unsigned_hash "$file")" ] \
    || fail "the run's $file isn't in SHA256SUMS-unsigned"
done
mac="$draft/keyseal-helper-$version-macos-universal"
"$src/helper/packaging/macos/compare-bundle.sh" "$mac.zip" "$work/ci-unsigned" "$notices"
"$src/helper/packaging/macos/compare-bundle.sh" "$mac.dmg" "$work/ci-unsigned" "$notices"
ditto -x -k "$mac.zip" "$work/unzipped"
app="$work/unzipped/KeySeal.app"
signature="$(codesign -dv "$app" 2>&1)"
if grep -qx 'Signature=adhoc' <<<"$signature"; then
  echo "Ad-hoc signed: not notarized (docs/code-signing-policy.md)."
else
  grep -q 'source=Notarized Developer ID' <<<"$(spctl -a -vv "$app" 2>&1)" || fail "the app isn't notarized"
  spctl -a -vv -t open --context context:primary-signature "$mac.dmg" || fail "the disk image isn't notarized"
fi

step "Linux"
if [ "$rebuild" = skip-rebuild ]; then
  echo "Skipped the rebuild (--skip-rebuild)."
else
  platforms=()
  pids=()
  started=$SECONDS
  # The same image and rustup-init as release.yml and docs/releasing.md,
  # once per architecture. The image is release.yml's
  # ubuntu:22.04@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956,
  # by the digest of that index's image for the architecture, which some
  # Docker stores can't keep two of under one index digest. The container
  # gets a copy of the source in /w/src and the packages in /w/draft, and its
  # last line is the rebuilt binary's SHA-256.
  for build in \
    "linux-x64 amd64 x86_64 5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4 98510ac07bb4545e389be502a8918b385c018bfe4ceeb5ac7e0375c782268b04" \
    "linux-arm64 arm64 aarch64 a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697 88881eb36da489f9ff8746ece8048ca16cc94f80e8cd3ae7e8335d8822631591"; do
    read -r platform deb_arch arch rustup_sha256 image_digest <<<"$build"
    image="ubuntu@sha256:$image_digest"
    linux="keyseal-helper-$version-$platform"
    cat >"$work/rebuild-$platform.sh" <<SCRIPT
set -e
apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential ca-certificates curl file git \\
  pkg-config libasound2-dev libfontconfig-dev libvulkan1 libwayland-dev libx11-xcb-dev libxkbcommon-x11-dev \\
  squashfs-tools >/dev/null
curl -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.29.2/$arch-unknown-linux-gnu/rustup-init
echo "$rustup_sha256  /tmp/rustup-init" | sha256sum -c -
chmod +x /tmp/rustup-init && /tmp/rustup-init -y -q --profile minimal --default-toolchain none
. "\$HOME/.cargo/env" && git config --global --add safe.directory /w/src
cd /w/src && (cd helper && rustup toolchain install)
helper/packaging/build-release.sh $platform /w/rebuilt >/dev/null
binary=/w/rebuilt/$linux
tar -xzOf /w/draft/$linux.tar.gz $linux/keyseal | cmp - "\$binary"
dpkg-deb --fsys-tarfile /w/draft/keyseal_${version}_$deb_arch.deb | tar -xO ./usr/bin/keyseal | cmp - "\$binary"
# The AppImage's file system starts where its runtime's ELF ends (the end of
# the section header table); unpacking it there doesn't run the runtime.
appimage=/w/draft/$linux.AppImage
shoff=\$(od -An -t u8 -j 40 -N 8 "\$appimage" | tr -d ' ')
shentsize=\$(od -An -t u2 -j 58 -N 2 "\$appimage" | tr -d ' ')
shnum=\$(od -An -t u2 -j 60 -N 2 "\$appimage" | tr -d ' ')
unsquashfs -q -n -o \$((shoff + shentsize * shnum)) -d /tmp/appimage "\$appimage" usr/bin/keyseal
cmp /tmp/appimage/usr/bin/keyseal "\$binary"
sha256sum "\$binary"
SCRIPT
    # Streamed in rather than mounted: nothing in the container can change
    # the scripts and files this script runs and signs afterwards.
    inputs=(src "rebuild-$platform.sh" "draft/$linux.tar.gz" "draft/keyseal_${version}_$deb_arch.deb" "draft/$linux.AppImage")
    container="docker run -i --rm --platform linux/$deb_arch $image sh -c 'mkdir /w && tar -xf - -C /w && sh /w/rebuild-$platform.sh'"
    log="$work/rebuild-$platform.log"
    case "$rebuild:$platform" in
      default:linux-x64 | rebuild-boat:*)
        # No stored secrets, no snapshot of what it held, and gone after
        # the TTL if this script can't delete it.
        created="$(run_boat new --no-env --no-snapshots --type large --ttl 7200 \
          --name "keyseal-rebuild-$version-$platform" --json)" || true
        sandbox="$(jq -r 'select(.event == "created") | .id' <<<"$created")"
        [ -z "$sandbox" ] || sandboxes+=("$sandbox")
        jq -e 'select(.event == "ready")' <<<"$created" >/dev/null || fail "starting a Boat sandbox for $platform"
        # Boat machines are x86_64. arm64 runs under QEMU user emulation,
        # registered from Ubuntu's own packages, not a third-party image.
        # apt reads from /dev/null, not the inputs on stdin.
        if [ "$deb_arch" = arm64 ]; then
          container="sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends qemu-user-static binfmt-support </dev/null >/dev/null && $container"
          container="sudo -n apt-get update -qq </dev/null >/dev/null && $container"
        fi
        where="in Boat sandbox $sandbox"
        remote=(run_boat ssh "$sandbox")
        ;;
      rebuild-host:*)
        where="on $rebuild_host"
        remote=(ssh "$rebuild_host")
        ;;
      default:linux-arm64 | rebuild-local:*)
        # Native on Apple silicon.
        where="in local Docker"
        remote=(sh -c)
        ;;
    esac
    echo "Rebuilding $platform $where; its output goes to $log."
    # Both at once; each reports when it ends.
    (
      if tar -C "$work" -cf - "${inputs[@]}" | "${remote[@]}" "$container" 2>"$log" | tail -1 >"$work/rebuilt-$platform"; then
        echo "The $platform rebuild finished after $(((SECONDS - started) / 60)) minutes."
      else
        echo "The $platform rebuild failed after $(((SECONDS - started) / 60)) minutes. The end of $log:" >&2
        tail -20 "$log" >&2
        exit 1
      fi
    ) &
    platforms+=("$platform")
    pids+=("$!")
  done
  failed=""
  for i in "${!pids[@]}"; do
    wait "${pids[$i]}" || failed="$failed ${platforms[$i]}"
  done
  [ -z "$failed" ] || fail "the rebuild or its packages:$failed"
  for platform in "${platforms[@]}"; do
    rebuilt="$(cat "$work/rebuilt-$platform")"
    [ "${rebuilt%% *}" = "$(unsigned_hash "keyseal-helper-$version-$platform")" ] \
      || fail "the $platform rebuild differs from the release"
    echo "The $platform rebuild equals the release binary, and the tarball, deb and AppImage hold it."
  done
fi

if $verify_only; then
  # A published release carries the signatures its publish run accepted.
  for file in keyseal-update.json SHA256SUMS; do
    [ ! -f "$draft/$file.sig" ] || "$src/helper/packaging/verify-signatures.sh" "$draft/$file" "$draft/$file.sig"
  done
  step "Every check passed; nothing signed (--verify-only)"
  outcome="$tag: every check passed."
  exit 0
fi

step "Signing with \"$key\""
for file in keyseal-update.json SHA256SUMS; do
  BW_SESSION="$bw_session" "$src/helper/packaging/sign-file.sh" bitwarden "$key" "$draft/$file" >"$work/$file-$signer.json"
done
echo "Wrote $work/keyseal-update.json-$signer.json and $work/SHA256SUMS-$signer.json."
if [ "${KEYSEAL_SIGN_ONLY:-}" = 1 ]; then
  echo "Send both to whoever publishes (KEYSEAL_SIGN_ONLY=1)."
  outcome="$tag: signed, not published (KEYSEAL_SIGN_ONLY=1)."
  exit 0
fi

step "Verifying the signatures with the pinned keys"
jq -cs '{signatures: .}' "$work"/keyseal-update.json-*.json >"$work/keyseal-update.json.sig"
jq -cs '{signatures: .}' "$work"/SHA256SUMS-*.json >"$work/SHA256SUMS.sig"
# Not with the draft's own helper: it is CI's build, and this script holds
# the Bitwarden session. The publish run checks the manifest again with a
# helper built from the tag.
"$src/helper/packaging/verify-signatures.sh" "$draft/keyseal-update.json" "$work/keyseal-update.json.sig"
"$src/helper/packaging/verify-signatures.sh" "$draft/SHA256SUMS" "$work/SHA256SUMS.sig"

step "Publishing"
# gh doesn't always say which run it started, so the publish run is the
# dispatched run that wasn't there before. Only this script starts them.
newest_dispatch() {
  gh run list --repo "$repo" --workflow release.yml --event workflow_dispatch --limit 1 \
    --json databaseId --jq '.[0].databaseId // empty'
}
before="$(newest_dispatch)"
gh workflow run release.yml --repo "$repo" --ref main -f tag="$tag" \
  -f signatures="$(cat "$work/keyseal-update.json.sig")" \
  -f checksum_signatures="$(cat "$work/SHA256SUMS.sig")" >/dev/null
publish_run=""
for _ in $(seq 30); do
  publish_run="$(newest_dispatch)"
  [ -z "$publish_run" ] || [ "$publish_run" = "$before" ] || break
  publish_run=""
  sleep 5
done
[ -n "$publish_run" ] || fail "the publish run didn't appear; follow it at https://github.com/$repo/actions/workflows/release.yml"
run_url="https://github.com/$repo/actions/runs/$publish_run"
echo "Waiting for the publish run: $run_url"
until [ "$(gh run view "$publish_run" --repo "$repo" --json status --jq .status)" = completed ]; do
  sleep 30
done
[ "$(gh run view "$publish_run" --repo "$repo" --json conclusion --jq .conclusion)" = success ] \
  || fail "the publish run failed: $run_url"
[ "$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)" = false ] \
  || fail "the publish run passed but $tag is still a draft"
[ "$(gh api "repos/$repo/releases/latest" --jq .tag_name)" = "$tag" ] \
  || fail "$tag is published but isn't the latest release, so helpers won't update to it"
outcome="$tag is published and latest."
echo "$outcome"
