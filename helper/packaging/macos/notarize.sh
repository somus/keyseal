#!/usr/bin/env bash
# Notarizes and staples a signed KeySeal.app or disk image:
#
#   helper/packaging/macos/notarize.sh <KeySeal.app | .dmg>
#
# Authenticates with an App Store Connect API key from the environment:
#   APPLE_API_KEY      path to the AuthKey_<id>.p8 file
#   APPLE_API_KEY_ID   its key id
#   APPLE_API_ISSUER   the issuer id
# An app is submitted as a zip, since only the app itself can be stapled.
set -euo pipefail

path="$1"
: "${APPLE_API_KEY:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER:?}"

submission="$path"
if [ -d "$path" ]; then
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  submission="$work/$(basename "$path").zip"
  ditto -c -k --keepParent "$path" "$submission"
fi

auth=(--key "$APPLE_API_KEY" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER")
result="$(xcrun notarytool submit "$submission" "${auth[@]}" --wait --timeout 30m --output-format json)"
echo "$result"
status="$(plutil -extract status raw -o - - <<<"$result")"
if [ "$status" != Accepted ]; then
  xcrun notarytool log "$(plutil -extract id raw -o - - <<<"$result")" "${auth[@]}" || true
  exit 1
fi
xcrun stapler staple "$path"
xcrun stapler validate "$path"
