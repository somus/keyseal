#!/usr/bin/env bash
# Regenerates the helper's app icons from brand/: AppIcon.icns for macOS,
# keyseal.ico for Windows and keyseal.svg for Linux. Run on macOS with
# rsvg-convert (librsvg) and ImageMagick installed; commit the results.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
packaging="$root/helper/packaging"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

iconset="$work/AppIcon.iconset"
mkdir "$iconset"
for size in 16 32 128 256 512; do
  rsvg-convert -w "$size" -h "$size" "$root/brand/keyseal-icon.svg" -o "$iconset/icon_${size}x${size}.png"
  rsvg-convert -w $((size * 2)) -h $((size * 2)) "$root/brand/keyseal-icon.svg" -o "$iconset/icon_${size}x${size}@2x.png"
done
iconutil -c icns "$iconset" -o "$packaging/macos/AppIcon.icns"

pngs=()
for size in 16 20 24 32 40 48 64 256; do
  rsvg-convert -w "$size" -h "$size" "$root/brand/keyseal-icon-windows.svg" -o "$work/win-$size.png"
  pngs+=("$work/win-$size.png")
done
magick "${pngs[@]}" "$packaging/windows/keyseal.ico"

cp "$root/brand/keyseal-icon.svg" "$packaging/linux/keyseal.svg"
