# Packaging

## macOS: the token worker

Several Indian token drivers ship only x86_64 dylibs. The universal helper runs as arm64 on Apple Silicon and can't load them, so for such a driver it starts `keyseal-token-worker`, which loads the driver under Rosetta and runs the PKCS#11 operations over JSON lines on its stdin and stdout (`crates/keyseal-core/src/worker.rs`).

The worker is built for x86_64 only. A universal worker would run its arm64 slice on Apple Silicon and fail to load the driver the same way. It goes beside the universal helper: in `Contents/MacOS/` of the app bundle, or in the same directory as `keyseal` outside a bundle. The helper looks for it only next to its own executable and refuses one that resolves, through a symlink say, to another directory.

```bash
cargo build --release -p keyseal-helper --target aarch64-apple-darwin
cargo build --release -p keyseal-helper -p keyseal-token-worker --target x86_64-apple-darwin
lipo -create -output KeySeal.app/Contents/MacOS/keyseal \
  target/aarch64-apple-darwin/release/keyseal \
  target/x86_64-apple-darwin/release/keyseal
cp target/x86_64-apple-darwin/release/keyseal-token-worker KeySeal.app/Contents/MacOS/
```

Sign the worker like the helper, with the hardened runtime and the `com.apple.security.cs.disable-library-validation` entitlement, since both load vendor driver dylibs. It is notarized as part of the bundle.

The worker needs Rosetta 2 (`softwareupdate --install-rosetta`). Without it the helper reports that the Intel-only driver needs Rosetta. On Intel Macs the helper loads every driver itself and never starts the worker.

To check the worker under Rosetta, build it for x86_64 and run its SoftHSM test with an x86_64 libsofthsm2 of the same version as the arm64 one that initialises the token:

```bash
cargo build -p keyseal-token-worker --target x86_64-apple-darwin
KEYSEAL_SOFTHSM_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
  KEYSEAL_X86_64_WORKER=target/x86_64-apple-darwin/debug/keyseal-token-worker \
  KEYSEAL_X86_64_SOFTHSM_MODULE=/path/to/x86_64/libsofthsm2.so \
  cargo test -p keyseal-token-worker
```
