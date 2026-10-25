#!/usr/bin/env bash
# Builds the unsigned release binary for one platform, reproducibly:
#
#   helper/packaging/build-release.sh <macos-universal|windows-x64|linux-x64> <out dir>
#
# CI and maintainers run this same script, so a rebuild matches the
# release byte for byte given the pinned Rust toolchain (rust-toolchain.toml),
# Cargo.lock, and the same platform C toolchain, which BUILDINFO records.
# Writes <out dir>/keyseal-helper-<version>-<platform>[.exe] and BUILDINFO, and
# for macOS keyseal-token-worker-<version>-macos-x86_64.
set -euo pipefail

platform="$1"
out="$2"
here="$(cd "$(dirname "$0")" && pwd)"
helper="$(dirname "$here")"
version="$(awk -F'"' '/^version = /{print $2; exit}' "$helper/Cargo.toml")"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
# rustup picks the toolchain from the working directory.
cd "$helper"

# Paths go into the binary through panic locations and C __FILE__ strings;
# map them to fixed names. rustc on Windows sees Windows paths.
native() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
target_dir="$helper/target/release-build"
# CFLAGS can't quote, so the mapped paths can't hold spaces.
case "$helper$cargo_home" in
  *" "*)
    echo "Build from a path without spaces (and CARGO_HOME without them)." >&2
    exit 2
    ;;
esac
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$helper" log -1 --format=%ct)}"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$target_dir"
rustflags=(
  -C strip=symbols
  "--remap-path-prefix=$(native "$helper")=/keyseal"
  "--remap-path-prefix=$(native "$cargo_home")=/cargo"
  "--remap-path-prefix=$(native "$target_dir")=/target"
)
# The same for C sources (ring), with clang and gcc; MSVC has no such flag.
if [ "$platform" != windows-x64 ]; then
  export CFLAGS="-ffile-prefix-map=$cargo_home=/cargo -ffile-prefix-map=$target_dir=/target"
fi

build() {
  local package="$1" target="$2"
  shift 2
  local flags=("${rustflags[@]}" "$@")
  RUSTFLAGS="${flags[*]}" \
    cargo build --release --locked -p "$package" --target "$target"
}

{
  echo "KeySeal $version $platform"
  echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
  rustc -vV
} >"$out/BUILDINFO"

case "$platform" in
  macos-universal)
    # ld64 hashes the object paths it lists for debuggers into LC_UUID.
    oso="-C link-arg=-Wl,-oso_prefix,$target_dir/"
    build keyseal-helper aarch64-apple-darwin "$oso"
    build keyseal-helper x86_64-apple-darwin "$oso"
    binary="$out/keyseal-helper-$version-macos-universal"
    lipo -create -output "$binary" \
      "$target_dir/aarch64-apple-darwin/release/keyseal" \
      "$target_dir/x86_64-apple-darwin/release/keyseal"
    # The token worker loads Intel-only drivers under Rosetta, so it is
    # x86_64 only (packaging/README.md).
    build keyseal-token-worker x86_64-apple-darwin "$oso"
    cp "$target_dir/x86_64-apple-darwin/release/keyseal-token-worker" \
      "$out/keyseal-token-worker-$version-macos-x86_64"
    { xcode-select -p; xcrun --show-sdk-version; ld -v 2>&1 | sed -n 1p; clang --version | sed -n 1p; } >>"$out/BUILDINFO"
    ;;
  windows-x64)
    # /Brepro replaces the link timestamp with a content hash. The C runtime
    # is linked in, so a PC without the Visual C++ Redistributable runs it.
    build keyseal-helper x86_64-pc-windows-msvc -C link-arg=/Brepro -C target-feature=+crt-static
    binary="$out/keyseal-helper-$version-windows-x64.exe"
    cp "$target_dir/x86_64-pc-windows-msvc/release/keyseal.exe" "$binary"
    # The static C runtime comes from the MSVC toolset and the Windows SDK,
    # so a rebuild needs the same versions of both.
    vswhere="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
    # vswhere prints a Windows path with a CRLF line end.
    vs="$(cygpath -u "$("$vswhere" -latest -property installationPath | tr -d '\r')")"
    {
      "$vswhere" -latest -property catalog_productDisplayVersion
      echo "MSVC $(tr -d '\r' <"$vs/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt")"
      echo "Windows SDK $(find "/c/Program Files (x86)/Windows Kits/10/Lib" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -V | tail -1)"
    } >>"$out/BUILDINFO"
    ;;
  linux-x64)
    build keyseal-helper x86_64-unknown-linux-gnu
    binary="$out/keyseal-helper-$version-linux-x64"
    cp "$target_dir/x86_64-unknown-linux-gnu/release/keyseal" "$binary"
    { ldd --version | sed -n 1p; cc --version | sed -n 1p; } >>"$out/BUILDINFO"
    ;;
  *)
    echo "Unknown platform $platform" >&2
    exit 2
    ;;
esac
echo "$binary"
