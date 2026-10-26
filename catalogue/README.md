# KeySeal driver catalogue

`catalogue.json` tells the helper which PKCS#11 module to load for a plugged-in DSC token, so integrators never name a driver path. It maps USB vendor and product ids to module paths per OS and architecture, with display names for the token and vendor. It is signed and versioned separately from the helper, so a new token or driver path ships without a helper release.

## Files

- `schema.json`: JSON Schema (2020-12) for `catalogue.json`.
- `catalogue.json`: the catalogue.
- `catalogue.json.sig`: detached signature, produced at release time, attached to the release and never committed.
- `SOURCES.md`: where every id and path came from.
- `tools/`: validate, sign and verify scripts (Bun, TypeScript).

## Format

```json
{
  "version": 3,
  "generatedAt": "2026-10-22T00:00:00Z",
  "tokens": [
    {
      "name": "Example Token",
      "vendor": "Example Vendor",
      "usb": [{ "vid": "abcd", "pid": "0001" }],
      "modules": {
        "macos-arm64": ["/usr/local/lib/libexample.dylib"],
        "windows-x64": ["C:\\Windows\\System32\\example_pkcs11.dll"],
        "linux-x64": ["/usr/lib/libexample.so"]
      },
      "notes": "optional free text",
      "cng": true
    }
  ]
}
```

- `version` is an integer that only increases. The helper keeps the highest version it has verified and refuses an older one, which blocks rollback to a catalogue with a removed or corrected path.
- `usb` ids are lowercase 4-digit hex. Each `vid:pid` pair belongs to at most one token; `tools/catalogue.ts` checks that across tokens because JSON Schema cannot. An empty `usb` array means no public source states the ids; ids are never guessed. Such tokens are still useful for the path scan.
- `modules` keys are `macos-arm64`, `macos-x64`, `windows-x64` and `linux-x64`. Each value is an ordered list of absolute paths, tried first to last. A token may omit platforms its vendor does not support.
- `cng: true` marks a Windows token known to work only through CNG, with no usable PKCS#11 module.

## How the helper uses it

The helper tries candidate module paths in this order. The first path that exists and loads wins.

1. The `KEYSEAL_PKCS11_MODULE` environment variable, a developer override. When set, it is the only candidate.
2. A module path from the user's `config.json`.
3. Catalogue match: enumerate USB devices, look up each `vid:pid`, and try that token's module paths for the current platform in order.
4. Path scan: every module path in the catalogue for the current platform.
5. The built-in list of known DSC driver paths in `helper/crates/keyseal-core/src/modules.rs`.
6. p11-kit, on Linux only.

On Windows, CNG is the last resort.

The helper verifies `catalogue.json.sig` against its pinned catalogue key before parsing the file. If the download or verification fails it keeps using the last verified catalogue, and falls back to the copy bundled at build time.

## Paths are never user-writable

Every path must be absolute and live under a system or vendor directory: `/usr/local/lib`, `/Library`, `/Applications`, `/usr/lib`, `/usr/lib64`, `/opt`, `C:\Windows\System32`, `C:\Program Files` or `C:\Program Files (x86)`. The schema enforces this with a `pattern` and rejects `.` and `..` segments, so a catalogue can never point the helper at a home directory, a temp directory or a relative path. A driver that only installs into a user-writable location stays out of the catalogue; users of that driver go through the explicit override.

## Updating

1. Edit `catalogue.json`. Bump `version` by one and set `generatedAt`.
2. Add or update the entry in `SOURCES.md` for every id or path you change. No source, no id.
3. Format, then run the tests. Do not reformat the file after signing: the signature covers the exact bytes.

   ```sh
   bunx oxfmt catalogue/catalogue.json
   cd catalogue && bun install && bun test
   ```

4. Sign with the catalogue key, check the signature, then attach `catalogue.json` and `catalogue.json.sig` to a KeySeal GitHub release:

   ```sh
   export BW_SESSION="$(bw unlock --raw)"
   helper/packaging/sign-file.sh bitwarden "KeySeal catalogue key" catalogue/catalogue.json > catalogue/catalogue.json.sig
   bw get notes "KeySeal catalogue key" | openssl pkey -pubout > /tmp/catalogue.pub.pem
   (cd catalogue && bun tools/verify.ts /tmp/catalogue.pub.pem)
   ```

## Signing

The signature file is `{ "keyId": <hex SHA-256 of the raw 32-byte Ed25519 public key>, "signature": <base64 Ed25519 over the exact bytes of catalogue.json> }`. `sign.ts` validates the catalogue before signing and `verify.ts` checks the key id, the signature and the schema.

Production signing uses the maintainer's catalogue keys, separate from the release keys (see `docs/design.md`, Release and updates). As with the release keys, there are two, both pinned in `CATALOGUE_KEYS` (`helper/crates/keyseal-core/src/catalogue.rs`): a primary in Bitwarden and a backup encrypted and kept offline. Both are made with `helper/packaging/new-key.sh`, and `helper/packaging/sign-file.sh` signs with either without writing the unencrypted key to disk. When the maintainer moves to YubiKeys, the catalogue key goes in PIV slot 9d, beside the release key in 9c. `tools/sign.ts` takes a key file and exists for development and tests only.

| Maintainer | Key | keyId (SHA-256 of the raw public key) |
| --- | --- | --- |
| Somasundaram Ayyappan (@somus) | primary, in Bitwarden | `c81f8529e7ecbe38ab150199fca32b3899e4e565713642bb28a9b794b76a24e4` |
| | backup, offline | `2dd4ca5fcc72ef45ca6dd011753cb530ce6fcc3ece9310cdd47108977ef3c32b` |

Throwaway dev key, kept outside the repository and never committed:

```sh
openssl genpkey -algorithm ed25519 -out /tmp/keyseal-catalogue-dev.pem
openssl pkey -in /tmp/keyseal-catalogue-dev.pem -pubout -out /tmp/keyseal-catalogue-dev.pub.pem
cd catalogue
bun tools/sign.ts /tmp/keyseal-catalogue-dev.pem
bun tools/verify.ts /tmp/keyseal-catalogue-dev.pub.pem
```

## Package

`@keyseal/catalogue-tools` is a standalone private package with its own `package.json` and lockfile. The root workspaces glob covers `packages/*` and `examples/*` only, so it does not include `catalogue/`. Run `bun install` in this directory before `bun test` here or from the repository root.
