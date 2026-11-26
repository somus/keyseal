#!/usr/bin/env bash
# Checks the deb's apt repository end to end: with throwaway keys made and
# used by the maintainers' own scripts (new-apt-key.sh, sign-apt-release.sh),
# builds the deb at 1.0.0 and 1.0.1 for both architectures with
# build-deb.sh, makes 1.0.1 a flat repository with make-apt-repo.sh, and
# serves it as a GitHub release does, releases/latest/download/<file>
# redirecting to releases/download/<tag>/<file>. In a clean container of
# each system it installs 1.0.0, points the source the deb added at the
# server, and requires apt to refuse the repository unsigned, signed by
# another key, and with Packages changed after signing, then `apt update`
# and `apt upgrade` to install 1.0.1. Then `apt remove` must leave nothing
# behind, source and key included.
#
#   scripts/ci/apt-upgrade.sh [<image>...]
#
# The binaries are stand-ins that print their version: the repository is
# under test, not the helper. Needs Docker, GnuPG 2.2 or later, dpkg-deb,
# ar, jq, OpenSSL and python3. The containers use the host's network.
set -euo pipefail

images=("$@")
[ "${#images[@]}" -gt 0 ] || images=(ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 ubuntu:26.10 debian:12 debian:13)
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
packaging="$root/helper/packaging"
work="$(mktemp -d)"
server=""
trap '[ -z "$server" ] || kill "$server"; rm -rf "$work"' EXIT
old=1.0.0
new=1.0.1
tag="helper-v$new"
SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct)"
export SOURCE_DATE_EPOCH

echo "== Throwaway keys, made and used by the maintainers' scripts"
# Each script makes its own GnuPG home under TMPDIR and must leave nothing.
export TMPDIR="$work/tmp"
mkdir "$TMPDIR"
pass=correct-horse
printf '%s\n%s\n' "$pass" "$pass" | "$packaging/new-apt-key.sh" offline "$work/key.asc" "$work/keyring.asc"
printf '%s\n%s\n' "$pass" "$pass" | "$packaging/new-apt-key.sh" offline "$work/stranger.asc" "$work/stranger-keyring.asc"
gpg --list-packets "$work/key.asc" | grep -q 'S2K' || { echo "The offline key isn't encrypted." >&2; exit 1; }
[ -z "$(ls -A "$TMPDIR")" ] || { echo "new-apt-key.sh left files in TMPDIR: $(ls -A "$TMPDIR")" >&2; exit 1; }

echo "== build-deb.sh refuses to build without the checked-in key"
# A copy of the packaging with a stand-in Cargo.toml per version, and never
# the checked-in keyring.
echo "stand-in notices" >"$work/notices.txt"
export KEYSEAL_NOTICES="$work/notices.txt"
for version in "$old" "$new"; do
  tree="$work/tree-$version"
  mkdir -p "$tree/helper/packaging/linux" "$work/bin" "$work/debs-$version"
  printf 'version = "%s"\n' "$version" >"$tree/helper/Cargo.toml"
  cp "$packaging/linux/build-deb.sh" "$packaging/linux/keyseal.desktop" "$packaging/linux/keyseal.svg" \
    "$packaging/linux/keyseal.sources" "$tree/helper/packaging/linux/"
  for platform in linux-x64 linux-arm64; do
    binary="$work/bin/keyseal-helper-$version-$platform"
    printf '#!/bin/sh\necho "keyseal %s"\n' "$version" >"$binary"
    chmod +x "$binary"
    if [ "$version" = "$old" ] && [ "$platform" = linux-x64 ]; then
      if "$tree/helper/packaging/linux/build-deb.sh" "$binary" "$work/debs-$version" 2>"$work/refused"; then
        echo "build-deb.sh built a deb without the apt keyring." >&2
        exit 1
      fi
      cat "$work/refused"
    fi
    KEYSEAL_TEST_APT_KEYRING="$work/keyring.asc" \
      "$tree/helper/packaging/linux/build-deb.sh" "$binary" "$work/debs-$version" >/dev/null
  done
done
ls "$work/debs-$old" "$work/debs-$new"

echo "== The repositories"
# good: as a release serves it. unsigned: no InRelease. stranger: signed by
# a key the deb doesn't hold. tampered: Packages changed after signing.
repo() { echo "$work/www/$1/releases/download/$tag"; }
for case in good unsigned stranger tampered; do
  mkdir -p "$(repo "$case")"
  cp "$work/debs-$new"/*.deb "$(repo "$case")/"
  "$packaging/linux/make-apt-repo.sh" "$new" "$(repo "$case")" >/dev/null
done
cat "$(repo good)/Release"
echo "$pass" | "$packaging/sign-apt-release.sh" offline "$work/key.asc" "$(repo good)/Release" >"$(repo good)/InRelease"
echo "$pass" | "$packaging/sign-apt-release.sh" offline "$work/stranger.asc" "$(repo stranger)/Release" >"$(repo stranger)/InRelease"
[ -z "$(ls -A "$TMPDIR")" ] || { echo "sign-apt-release.sh left files in TMPDIR: $(ls -A "$TMPDIR")" >&2; exit 1; }
cp "$(repo good)/InRelease" "$(repo tampered)/InRelease"
sed -i "s/^Version: $new$/Version: 1.0.2/" "$(repo tampered)/Packages"
unset TMPDIR

echo "== verify-apt-release.sh"
"$packaging/verify-apt-release.sh" "$(repo good)/Release" "$(repo good)/InRelease" "$work/keyring.asc"
for refused in "stranger/InRelease good/Release" "good/InRelease tampered/Packages"; do
  read -r signed file <<<"$refused"
  if "$packaging/verify-apt-release.sh" "$work/www/${file%%/*}/releases/download/$tag/${file#*/}" \
    "$work/www/${signed%%/*}/releases/download/$tag/${signed#*/}" "$work/keyring.asc" 2>/dev/null; then
    echo "verify-apt-release.sh accepted $signed for $file." >&2
    exit 1
  fi
done
echo "verify-apt-release.sh refuses another key's signature and a file that isn't the one signed."

echo "== The server"
port=8765
cat >"$work/server.py" <<'PY'
import http.server, posixpath, sys

root, tag, port = sys.argv[1], sys.argv[2], int(sys.argv[3])

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=root, **kwargs)

    # As GitHub does: releases/latest/download/<file> redirects to the
    # latest release's file, after resolving the ./ a flat repository's
    # paths hold.
    def send_head(self):
        path = posixpath.normpath(self.path)
        case, latest, name = path.lstrip("/").partition("/releases/latest/download/")
        if latest:
            self.send_response(302)
            self.send_header("Location", f"/{case}/releases/download/{tag}/{name}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        return super().send_head()

http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
python3 "$work/server.py" "$work/www" "$tag" "$port" 2>"$work/server.log" &
server=$!
for _ in $(seq 50); do
  curl -fsS -o /dev/null "http://127.0.0.1:$port/good/releases/latest/download/./InRelease" 2>/dev/null && break
  sleep 0.2
done
curl -fsS -o /dev/null "http://127.0.0.1:$port/good/releases/latest/download/./InRelease"

cat >"$work/in-container.sh" <<'SH'
set -euo pipefail
port="$1" old="$2" new="$3"
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
echo "$PRETTY_NAME, apt $(dpkg-query -W -f '${Version}' apt), verifier: $(command -v sqv || command -v gpgv)"
apt-get update -qq
apt-get install -y -qq --no-install-recommends "/w/debs-$old/keyseal_${old}_$(dpkg --print-architecture).deb" >/dev/null
keyseal
source=/etc/apt/sources.list.d/keyseal.sources
keyring=/usr/share/keyrings/keyseal-archive-keyring.asc
cmp "$source" /w/keyseal.sources
cmp "$keyring" /w/keyring.asc
point() { sed -i "s#^URIs: .*#URIs: http://127.0.0.1:$port/$1/releases/latest/download#" "$source"; }
candidate() { apt-cache policy keyseal | awk '$1 == "Candidate:" { print $2 }'; }
for case in unsigned stranger tampered; do
  point "$case"
  if apt-get update >/tmp/update.log 2>&1; then
    cat /tmp/update.log
    echo "apt update accepted the $case repository." >&2
    exit 1
  fi
  [ "$(candidate)" = "$old" ] || { echo "apt offers $(candidate) from the $case repository." >&2; exit 1; }
  echo "$case refused: $(grep -m1 -E '^(E|W): .*(keyseal|127\.0\.0\.1)' /tmp/update.log)"
done
point good
apt-get update >/tmp/update.log 2>&1 || { cat /tmp/update.log; exit 1; }
! grep -E '^(E|W):' /tmp/update.log || { echo "apt update warned." >&2; exit 1; }
[ "$(candidate)" = "$new" ]
apt-get upgrade -y -qq >/dev/null
keyseal
[ "$(keyseal)" = "keyseal $new" ]
# The upgrade puts back the shipped source, which names GitHub.
cmp "$source" /w/keyseal.sources
apt-get remove -y -qq keyseal >/dev/null
[ ! -e "$source" ] && [ ! -e "$keyring" ] || { echo "apt remove left the source or the key." >&2; exit 1; }
# With no conffiles and no maintainer scripts, nothing is left to purge.
! dpkg-query -W keyseal 2>/dev/null || { echo "dpkg still has keyseal after apt remove." >&2; exit 1; }
apt-get update >/tmp/update.log 2>&1 || { cat /tmp/update.log; exit 1; }
! grep -i keyseal /tmp/update.log || { echo "apt still reads the repository." >&2; exit 1; }
echo "Upgraded $old to $new through apt; apt remove left nothing to purge."
SH
cp "$packaging/linux/keyseal.sources" "$work/"

failed=""
for image in "${images[@]}"; do
  echo "== $image"
  if ! docker run --rm --network host -v "$work:/w:ro" "$image" bash /w/in-container.sh "$port" "$old" "$new"; then
    failed="$failed $image"
  fi
done
echo "== The server's log"
grep -E '"GET /good/' "$work/server.log" | sed 's/^.*\] //' | sort | uniq -c
[ -z "$failed" ] || { echo "FAILED on:$failed" >&2; exit 1; }
echo "Every system upgraded through the signed repository and refused the others: ${images[*]}"
