#!/usr/bin/env bash
# Checks a draft helper release, signs it and starts the publish run, on a
# maintainer's Mac (docs/releasing.md, steps 4 to 6):
#
#   helper/packaging/release.sh <version> [--skip-rebuild | --rebuild-host <ssh host>]
#
# 1. Downloads the draft and clones its tag, so every check runs the
#    tagged scripts.
# 2. Checks keyseal-update.json and SHA256SUMS against the assets, the
#    Windows zip, and the macOS zip and disk image against the unsigned
#    binaries the release run built (compare-bundle.sh), with their Developer
#    ID or ad-hoc signature.
# 3. Rebuilds the Linux binary in the pinned container and requires it to
#    equal SHA256SUMS-unsigned and the binary in the tarball, deb and
#    AppImage. It takes about 15 minutes under emulation on Apple silicon;
#    --rebuild-host runs it natively on an x86_64 Linux machine with Docker
#    instead, streaming the source and the Linux packages to a throwaway
#    container there over SSH, so nothing is written on that machine but
#    Docker's image cache. --skip-rebuild skips it, accepting that CI built
#    what the tag holds.
# 4. Signs both files with the release key in Bitwarden
#    ($KEYSEAL_RELEASE_KEY, by default "KeySeal release key"), verifies the
#    signatures with the draft's own helper and verify-signatures.sh, and,
#    once you confirm, starts the publish run, which then waits for approval
#    of the `release` environment.
#
# With a THRESHOLD above 1 each maintainer runs it with KEYSEAL_SIGN_ONLY=1
# and sends their two .json entries; whoever publishes puts every entry in
# the work directory before running it without.
#
# Needs gh, jq, git, docker, bw, OpenSSL 3 or later and the Xcode command
# line tools. Works in $KEYSEAL_RELEASE_DIR, by default
# /tmp/keyseal-release-<version>, which must not hold a space.
set -euo pipefail

usage() {
  echo "usage: $0 <version> [--skip-rebuild | --rebuild-host <ssh host>]" >&2
  exit 2
}
version="${1:-}"
skip_rebuild=false
rebuild_host=""
case "${2:-}" in
  "") ;;
  --skip-rebuild) skip_rebuild=true ;;
  --rebuild-host) rebuild_host="${3:-}"; [ -n "$rebuild_host" ] || usage ;;
  *) usage ;;
esac
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

tag="helper-v$version"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
key="${KEYSEAL_RELEASE_KEY:-KeySeal release key}"
work="${KEYSEAL_RELEASE_DIR:-/tmp/keyseal-release-$version}"
signer="$(gh api user --jq .login)"
step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAILED: $*" >&2; exit 1; }

case "$(openssl version)" in
  "OpenSSL "[3-9]*) ;;
  *) fail "needs OpenSSL 3 or later first on the PATH, not $(openssl version)" ;;
esac
[ "$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)" = true ] \
  || fail "$tag is not a draft release in $repo"

step "Downloading the draft and the tagged source into $work"
rm -rf "$work/draft" "$work/src" "$work/ci-unsigned" "$work/mine" "$work/unzipped" "$work/rebuilt" "$work/rebuild.sh"
mkdir -p "$work"
gh release download "$tag" --repo "$repo" --dir "$work/draft"
git clone -q --branch "$tag" --depth 1 "https://github.com/$repo.git" "$work/src"
src="$work/src"
draft="$work/draft"
unsigned_hash() { awk -v f="$1" '$2 == f { print $1 }' "$draft/SHA256SUMS-unsigned"; }

step "keyseal-update.json and SHA256SUMS describe the assets"
"$src/helper/packaging/make-manifest.sh" "$version" "$draft" "$work/mine" >/dev/null
cmp "$work/mine/keyseal-update.json" "$draft/keyseal-update.json" || fail "keyseal-update.json"
cmp "$work/mine/SHA256SUMS" "$draft/SHA256SUMS" || fail "SHA256SUMS"
jq . "$draft/keyseal-update.json"

step "Windows"
win="$draft/keyseal-helper-$version-windows-x64"
[ "$(shasum -a 256 "$win.exe" | cut -d' ' -f1)" = "$(unsigned_hash "keyseal-helper-$version-windows-x64.exe")" ] \
  || fail "the update exe isn't the unsigned build"
[ "$(unzip -Z1 "$win.zip" | sort | tr '\n' ' ')" = "install.cmd keyseal.exe " ] || fail "the zip holds other files"
unzip -p "$win.zip" keyseal.exe | cmp - "$win.exe" || fail "the zip's keyseal.exe"
# The Windows checkout gives install.cmd CRLF line endings.
unzip -p "$win.zip" install.cmd | tr -d '\r' | cmp - "$src/helper/packaging/windows/install.cmd" \
  || fail "the zip's install.cmd"
echo "The zip holds the update exe and install.cmd."

step "macOS"
run="$(gh run list --repo "$repo" --workflow release.yml --event push --limit 20 \
  --json databaseId,headBranch,conclusion \
  --jq "map(select(.headBranch == \"$tag\" and .conclusion == \"success\"))[0].databaseId")"
[ -n "$run" ] && [ "$run" != null ] || fail "no successful release run for $tag"
gh run download "$run" --repo "$repo" --name unsigned-macos-universal --dir "$work/ci-unsigned"
for file in "keyseal-helper-$version-macos-universal" "keyseal-token-worker-$version-macos-x86_64"; do
  [ "$(shasum -a 256 "$work/ci-unsigned/$file" | cut -d' ' -f1)" = "$(unsigned_hash "$file")" ] \
    || fail "the run's $file isn't in SHA256SUMS-unsigned"
done
mac="$draft/keyseal-helper-$version-macos-universal"
"$src/helper/packaging/macos/compare-bundle.sh" "$mac.zip" "$work/ci-unsigned"
"$src/helper/packaging/macos/compare-bundle.sh" "$mac.dmg" "$work/ci-unsigned"
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
if $skip_rebuild; then
  echo "Skipped the rebuild (--skip-rebuild)."
else
  # The same image and rustup-init as release.yml and docs/releasing.md. The
  # container finds the source in /w/src and the packages in /w/draft, and
  # its last line is the rebuilt binary's SHA-256.
  image=ubuntu:22.04@sha256:0a9887931b0e38af2e3487ed39e29436b0535c4f3f52e57745baaf79d1898956
  linux="keyseal-helper-$version-linux-x64"
  cat >"$work/rebuild.sh" <<SCRIPT
set -e
apt-get update -qq && apt-get install -y -qq --no-install-recommends build-essential ca-certificates curl file git \\
  pkg-config libasound2-dev libfontconfig-dev libvulkan1 libwayland-dev libx11-xcb-dev libxkbcommon-x11-dev >/dev/null
curl -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.29.2/x86_64-unknown-linux-gnu/rustup-init
echo "5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4  /tmp/rustup-init" | sha256sum -c -
chmod +x /tmp/rustup-init && /tmp/rustup-init -y -q --profile minimal --default-toolchain none
. "\$HOME/.cargo/env" && git config --global --add safe.directory /w/src
cd /w/src && (cd helper && rustup toolchain install)
helper/packaging/build-release.sh linux-x64 /w/rebuilt >/dev/null
binary=/w/rebuilt/$linux
tar -xzOf /w/draft/$linux.tar.gz $linux/keyseal | cmp - "\$binary"
dpkg-deb --fsys-tarfile /w/draft/keyseal_${version}_amd64.deb | tar -xO ./usr/bin/keyseal | cmp - "\$binary"
cd /tmp && cp /w/draft/$linux.AppImage a.AppImage && chmod +x a.AppImage
./a.AppImage --appimage-extract >/dev/null && cmp squashfs-root/usr/bin/keyseal "\$binary"
sha256sum "\$binary"
SCRIPT
  if [ -n "$rebuild_host" ]; then
    echo "Rebuilding on $rebuild_host."
    rebuilt="$(tar -C "$work" -cf - src rebuild.sh "draft/$linux.tar.gz" "draft/keyseal_${version}_amd64.deb" \
      "draft/$linux.AppImage" \
      | ssh "$rebuild_host" "docker run -i --rm --platform linux/amd64 $image sh -c 'mkdir /w && tar -xf - -C /w && sh /w/rebuild.sh'" \
      | tail -1)" || fail "the Linux rebuild or its packages on $rebuild_host"
  else
    rebuilt="$(docker run --rm --platform linux/amd64 -v "$work":/w "$image" sh /w/rebuild.sh | tail -1)" \
      || fail "the Linux rebuild or its packages"
  fi
  [ "${rebuilt%% *}" = "$(unsigned_hash "$linux")" ] || fail "the Linux rebuild differs from the release"
  echo "The rebuild equals the release binary, and the tarball, deb and AppImage hold it."
fi

step "Signing with \"$key\""
[ "$(bw status | jq -r .status)" = unlocked ] \
  || fail 'Bitwarden is locked: export BW_SESSION="$(bw unlock --raw)"'
for file in keyseal-update.json SHA256SUMS; do
  "$src/helper/packaging/sign-file.sh" bitwarden "$key" "$draft/$file" >"$work/$file-$signer.json"
done
echo "Wrote $work/keyseal-update.json-$signer.json and $work/SHA256SUMS-$signer.json."
if [ "${KEYSEAL_SIGN_ONLY:-}" = 1 ]; then
  echo "Send both to whoever publishes (KEYSEAL_SIGN_ONLY=1)."
  exit 0
fi

step "Verifying the signatures with the pinned keys"
jq -cs '{signatures: .}' "$work"/keyseal-update.json-*.json >"$work/keyseal-update.json.sig"
jq -cs '{signatures: .}' "$work"/SHA256SUMS-*.json >"$work/SHA256SUMS.sig"
"$app/Contents/MacOS/keyseal" update verify "$draft/keyseal-update.json" "$work/keyseal-update.json.sig"
"$src/helper/packaging/verify-signatures.sh" "$draft/SHA256SUMS" "$work/SHA256SUMS.sig"

step "Publishing"
read -rp "Start the publish run for $tag? [y/N] " answer
[ "$answer" = y ] || { echo "Not published. The signatures are in $work."; exit 0; }
gh workflow run release.yml --repo "$repo" --ref main -f tag="$tag" \
  -f signatures="$(cat "$work/keyseal-update.json.sig")" \
  -f checksum_signatures="$(cat "$work/SHA256SUMS.sig")"
echo "Started. Approve the release environment: https://github.com/$repo/actions/workflows/release.yml"
