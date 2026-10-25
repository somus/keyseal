# Signing the update manifest and SHA256SUMS

Installed helpers update only to a release whose `keyseal-update.json` carries
Ed25519 signatures from at least `THRESHOLD` distinct keys in
`RELEASE_KEYS` (`helper/crates/keyseal-core/src/update.rs`). First installs
are downloads, so maintainers sign the release's `SHA256SUMS`, which lists
every asset, with the same keys and the same threshold, and the release
workflow publishes only when both verify. Each signature is made offline on
a maintainer's YubiKey. CI never holds a release key.

The format is in `spec/protocol-v1.md` section 13. The policy around it is
in `docs/code-signing-policy.md`; the full release sequence is in
`docs/releasing.md`.

## Tools

- A YubiKey 5 with firmware 5.7 or later, the first with Ed25519 in the
  PIV applet.
- `yubico-piv-tool` 2.5.0 or later (Ed25519 support; 2.7.3 is current).
- `openssl`, `jq`, `sha256sum` (`shasum -a 256` on macOS) and `base64`.

## Once per YubiKey: make a key and pin it

Each maintainer keeps two YubiKeys, a daily one and a backup in a separate
place, and both keys are pinned. The private key is generated on the device
and never leaves it.

```sh
yubico-piv-tool -a generate -s 9c -A ED25519 -o release-key.pem
# The raw 32-byte public key and its keyId:
openssl pkey -pubin -in release-key.pem -outform DER | tail -c 32 > release-key.raw
sha256sum release-key.raw              # the keyId
xxd -i release-key.raw                 # bytes for RELEASE_KEYS
```

Add the bytes to `RELEASE_KEYS` in a reviewed commit, with a comment naming
the maintainer and which of their keys it is, and add the keyId to the key
table in `docs/code-signing-policy.md`. A key reaches users only in a
release signed by keys they already trust.

## Every release: check, then sign

Below, `<v>` is the version, `draft` holds the draft's assets and `rebuilt`
the unsigned binaries you build in step 2.

1. Download every asset of the draft release the release workflow made:

   ```sh
   gh release download helper-v<v> --repo <owner>/keyseal --dir draft
   ```

2. Rebuild the unsigned binaries yourself into `rebuilt` and compare them
   with `draft/SHA256SUMS-unsigned` (see "Reproducing a release" in
   `docs/releasing.md`). Don't sign if any differ.
3. Check that `keyseal-update.json` and `SHA256SUMS` describe the draft's
   assets, and nothing else:

   ```sh
   helper/packaging/make-manifest.sh <v> draft mine
   cmp mine/keyseal-update.json draft/keyseal-update.json
   cmp mine/SHA256SUMS draft/SHA256SUMS
   ls draft                     # the files SHA256SUMS lists, and SHA256SUMS
   jq . draft/keyseal-update.json # version, file names, hashes
   ```

4. Check that every asset holds the binaries you rebuilt. Don't sign if any
   check fails.
   - macOS, the update zip and the disk image. The app in them is
     Developer ID signed and notarized, so it isn't byte for byte the
     rebuild; `compare-bundle.sh` takes the signature out of each
     executable and compares the rest (the method is in the script):

     ```sh
     helper/packaging/macos/compare-bundle.sh draft/keyseal-helper-<v>-macos-universal.zip rebuilt
     helper/packaging/macos/compare-bundle.sh draft/keyseal-helper-<v>-macos-universal.dmg rebuilt
     ditto -x -k draft/keyseal-helper-<v>-macos-universal.zip unzipped
     spctl -a -vv unzipped/KeySeal.app   # accepted, source=Notarized Developer ID
     spctl -a -vv -t open --context context:primary-signature draft/keyseal-helper-<v>-macos-universal.dmg
     ```

   - Windows: the update exe is the unsigned binary, and the zip holds it
     and `install.cmd`:

     ```sh
     cmp draft/keyseal-helper-<v>-windows-x64.exe rebuilt/keyseal-helper-<v>-windows-x64.exe
     unzip -l draft/keyseal-helper-<v>-windows-x64.zip   # keyseal.exe and install.cmd only
     unzip -p draft/keyseal-helper-<v>-windows-x64.zip keyseal.exe | cmp - rebuilt/keyseal-helper-<v>-windows-x64.exe
     unzip -p draft/keyseal-helper-<v>-windows-x64.zip install.cmd | cmp - helper/packaging/windows/install.cmd
     ```

   - Linux: the tarball, deb and AppImage, which is also the update
     asset, hold the unsigned binary as `keyseal`. Run these on Linux, in the
     build container for instance, where `dpkg-deb` and the AppImage run:

     ```sh
     b=rebuilt/keyseal-helper-<v>-linux-x64
     tar -xzOf draft/keyseal-helper-<v>-linux-x64.tar.gz keyseal-helper-<v>-linux-x64/keyseal | cmp - "$b"
     dpkg-deb --fsys-tarfile draft/keyseal_<v>_amd64.deb | tar -xO ./usr/bin/keyseal | cmp - "$b"
     draft/keyseal-helper-<v>-linux-x64.AppImage --appimage-extract >/dev/null   # into squashfs-root
     cmp squashfs-root/usr/bin/keyseal "$b"
     ```

5. Sign the exact bytes of both files. Each must be under 3072 bytes, the
   limit `yubico-piv-tool` signs in one piece; both are far smaller.

   ```sh
   key_id="$(sha256sum release-key.raw | cut -d' ' -f1)"
   for file in keyseal-update.json SHA256SUMS; do
     test "$(wc -c < "draft/$file")" -lt 3072
     yubico-piv-tool -a verify-pin --sign -s 9c -A ED25519 \
       -i "draft/$file" -o "$file.raw"
     test "$(wc -c < "$file.raw")" -eq 64
     jq -cn --arg keyId "$key_id" \
       --arg signature "$(base64 < "$file.raw" | tr -d '\n')" \
       '{keyId: $keyId, signature: $signature}' > "$file-<your name>.json"
   done
   ```

   PureEdDSA signs the message itself, so `-i` takes the file, not a
   digest of it. The PIN is asked for each file.
6. Send `keyseal-update.json-<your name>.json` and
   `SHA256SUMS-<your name>.json` to whoever publishes. They combine the
   entries and check them: the manifest with the helper's own verifier,
   using a release build of the helper (the pinned keys are compiled in),
   and `SHA256SUMS` with the same rule against the keys in the tagged
   source (`verify-signatures.sh` needs OpenSSL 3):

   ```sh
   jq -cs '{signatures: .}' keyseal-update.json-*.json > keyseal-update.json.sig
   jq -cs '{signatures: .}' SHA256SUMS-*.json > SHA256SUMS.sig
   keyseal update verify draft/keyseal-update.json keyseal-update.json.sig
   helper/packaging/verify-signatures.sh draft/SHA256SUMS SHA256SUMS.sig
   ```

7. Publish with the "release" workflow's manual run, pasting the contents
   of `keyseal-update.json.sig` and `SHA256SUMS.sig`. It runs the same
   verification, checks every asset against `SHA256SUMS`, and publishes
   nothing if any check fails.
