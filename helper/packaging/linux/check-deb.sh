#!/usr/bin/env bash
# Installs the deb in <dir> for this system's architecture with apt, from
# its Depends alone, and checks that KeySeal starts and that every library
# it opens at run time came with it. Run it in a clean container:
#
#   docker run --rm -v "$PWD:/w" -w /w ubuntu:22.04 bash helper/packaging/linux/check-deb.sh dist
set -euo pipefail

dir="$1"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends "./$dir/"keyseal_*_"$(dpkg --print-architecture)".deb >/dev/null
keyseal --version
# doctor exits 1 when no token driver is installed, as here; a missing
# library makes the loader exit 127 first.
status=0
keyseal doctor || status=$?
if [ "$status" -gt 1 ]; then
  echo "keyseal doctor exited with $status." >&2
  exit 1
fi
# GPUI opens these with dlopen when it opens a window, so the loader doesn't
# check them at start.
missing=0
for library in libvulkan.so.1 libwayland-client.so.0; do
  if ! ldconfig -p | grep -q "^[[:space:]]*$library "; then
    echo "$library isn't installed." >&2
    missing=1
  fi
done
exit "$missing"
