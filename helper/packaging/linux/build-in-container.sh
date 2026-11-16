#!/bin/sh
# Builds the Linux release binary inside the pinned Ubuntu 22.04 container:
# installs the build packages, rustup-init pinned by version and SHA-256 and
# the toolchain rust-toolchain.toml pins, then runs build-release.sh.
#
#   helper/packaging/linux/build-in-container.sh <linux-x64|linux-arm64> <out dir>
#
# Run it as root from the root of the source, in the image release.yml's
# build-linux job names in `container:`. That job runs it, and
# sign-release.sh runs its own checkout's copy on the tagged source, so a
# tag made before this script existed rebuilds with the same recipe. The
# binary depends on every command here: a change needs a release that
# reproduces. Prints only build-release.sh's output, the binary's path; the
# rest goes to stderr.
set -eu

platform="$1"
out="$2"
case "$platform" in
  linux-x64)
    arch=x86_64
    rustup_sha256=5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4
    ;;
  linux-arm64)
    arch=aarch64
    rustup_sha256=a9c168dbea81a84671c6b7a5c1795cb0eb699020110d107ddfca427bd797e697
    ;;
  *)
    echo "Unknown platform $platform" >&2
    exit 2
    ;;
esac

{
  # GPUI's Linux build packages, the list in helper/linux-build-packages.txt
  # (written out here, since a tag older than that file rebuilds with this
  # script), plus the tools and pkg-config the runner images have and the
  # container lacks. Versions are whatever jammy serves that day; BUILDINFO
  # records the C toolchain.
  apt-get update
  apt-get install -y --no-install-recommends build-essential ca-certificates curl file git \
    pkg-config libasound2-dev libfontconfig-dev libvulkan1 libwayland-dev libx11-xcb-dev libxkbcommon-x11-dev
  # The source belongs to another user than the container's root.
  git config --global --add safe.directory "$PWD"
  curl --proto '=https' --tlsv1.2 -fsSLo /tmp/rustup-init \
    "https://static.rust-lang.org/rustup/archive/1.29.2/$arch-unknown-linux-gnu/rustup-init"
  echo "$rustup_sha256  /tmp/rustup-init" | sha256sum -c -
  chmod +x /tmp/rustup-init
  /tmp/rustup-init -y --profile minimal --default-toolchain none
  rm /tmp/rustup-init
  . "$HOME/.cargo/env"
  (cd helper && rustup toolchain install)
} >&2
helper/packaging/build-release.sh "$platform" "$out"
