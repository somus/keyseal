# Quickstart without a token

This page takes you from a clean checkout to a signed PDF without a USB token. Docker Compose runs the signing service and the [reference server](../examples/reference-server/), a SoftHSM software token stands in for the USB token, and a helper built from the checkout signs. It takes about fifteen minutes, most of it building the helper.

The test CA, its certificates and the token are for trying KeySeal out only. Anyone can make the same kind of CA, the token's PIN is `1234`, and the service token in the compose file is public. Don't point the quickstart's service at real documents, and don't trust its CA anywhere else.

```
 browser ──> reference server ──> signing service       (Docker Compose, 127.0.0.1 only)
               127.0.0.1:8787      127.0.0.1:8090
                   ▲                trusts the test CA
                   │ http://127.0.0.1:8787, allowed by KEYSEAL_ALLOW_INSECURE_ORIGINS=1
 keyseal helper ───┘  (from a terminal)
   │ KEYSEAL_PKCS11_MODULE
 SoftHSM token: test keys and certificates, PIN 1234
```

## What you need

These steps are for Linux; [macOS and Windows](#macos-and-windows) differ in how SoftHSM is installed. On Debian or Ubuntu:

- Docker with the Compose plugin.
- SoftHSM 2, OpenSC (for `pkcs11-tool`), OpenSSL, curl and jq: `sudo apt install softhsm2 opensc openssl curl jq`. The SoftHSM module is then `/usr/lib/softhsm/libsofthsm2.so`.
- Rust through [rustup](https://rustup.rs) (the helper's `rust-toolchain.toml` picks the version) and GPUI's build dependencies: `sudo apt install build-essential libasound2-dev libfontconfig-dev libvulkan1 libwayland-dev libx11-xcb-dev libxkbcommon-x11-dev`.

You don't need Bun or Python: the service and the reference server run in containers.

## 1. Make the test token

```sh
git clone https://github.com/somus/keyseal.git
cd keyseal/examples/reference-server
module=/usr/lib/softhsm/libsofthsm2.so
../../scripts/ci/softhsm-token.sh "$PWD/quickstart/token" "$module"
```

This is the same script the end-to-end test uses. In `quickstart/token` it writes a SoftHSM token labelled `keyseal-e2e` with the user PIN `1234`, a throwaway CA, and keys on the token with certificates that CA issued: `rsa` (RSA-2048), `p256`, `p384`, `bp256` and `bp384` (brainpoolP256r1 and P384r1), `auth` (an RSA key that needs the PIN for every signature) and `dsig` (a certificate with digitalSignature but not nonRepudiation, which a default job doesn't accept). The CA's certificate is in `quickstart/token/roots/ca.pem`, which the signing service trusts in the next step. The CA and the certificates are valid for two days; to make a new set, run `rm -rf quickstart` and the script again, then `docker compose restart service`.

Check that the token holds the certificates:

```sh
export SOFTHSM2_CONF="$PWD/quickstart/token/softhsm2.conf"
pkcs11-tool --module "$module" --list-objects --type cert
```

## 2. Start the service and the reference server

```sh
docker compose up --build --detach
curl -fsS http://127.0.0.1:8090/health
```

[compose.yaml](../examples/reference-server/compose.yaml) builds both images from this checkout, so they match the helper you build next; the [published service image](../service/README.md#docker) may be older than the checkout. The service trusts the test CA through `SIGNING_EXTRA_TRUST_ROOTS_DIR`, beside the bundled CCA India roots, and `/health` counts its roots with the others. It signs without a timestamp, so it works offline; `SIGNING_TSA_URL=http://timestamp.digicert.com docker compose up --build --detach` adds one. Revocation data isn't fetched (`SIGNING_ALLOW_FETCHING` is off), and the test certificates name no CRL or OCSP responder anyway.

Both containers listen on 127.0.0.1 only. If port 8090 is taken, run `export KEYSEAL_QUICKSTART_SERVICE_PORT=18090` before `docker compose up` and use that port wherever this page says 8090; the service's port is published only so you can check the signed PDF from your computer. The reference server reaches the service at `http://service:8080` with the shared bearer token, and puts `http://127.0.0.1:8787` in its `keyseal://` links, which is where the helper on your computer finds it.

## 3. Build the helper

```sh
(cd ../../helper && cargo build -p keyseal-helper)
```

The helper is `../../helper/target/debug/keyseal`. It needs four settings for the quickstart, which you give it in the terminal you'll run it from:

```sh
export SOFTHSM2_CONF="$PWD/quickstart/token/softhsm2.conf"
export KEYSEAL_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export KEYSEAL_ALLOW_INSECURE_ORIGINS=1
export KEYSEAL_CONFIG_DIR="$PWD/quickstart/helper"
```

- `KEYSEAL_PKCS11_MODULE` makes the helper load SoftHSM instead of looking for the drivers of plugged-in tokens, and `SOFTHSM2_CONF` tells SoftHSM where the test token is.
- `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` lets the helper accept `http://127.0.0.1:8787`. Without it the helper accepts https origins only. Such an origin is never stored as trusted, and every prompt flags it as insecure.
- `KEYSEAL_CONFIG_DIR` keeps this helper's settings and log in `quickstart/helper`, away from an installed helper's.

A helper the browser starts from a `keyseal://` link gets none of these, so in this quickstart you copy the link from the page and run it from this terminal instead. If you have a released KeySeal installed, the browser may offer to open the link in it: decline, since it refuses the plain-HTTP origin.

## 4. Sign a PDF

Open http://127.0.0.1:8787/ in a browser, choose a PDF and select Create signing job. Any PDF works; to make a blank one-page PDF, run:

```sh
docker compose exec -T service /app/.venv/bin/python -c '
import io, sys
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.writer import PdfFileWriter
w = PdfFileWriter()
w.insert_page(generic.DictionaryObject({
    generic.NameObject("/Type"): generic.NameObject("/Page"),
    generic.NameObject("/MediaBox"): generic.ArrayObject([generic.NumberObject(n) for n in (0, 0, 595, 842)]),
    generic.NameObject("/Resources"): generic.DictionaryObject(),
}))
out = io.BytesIO()
w.write(out)
sys.stdout.buffer.write(out.getvalue())
' >sample.pdf
```

The page shows the job as pending, with its `keyseal://sign?...` link below. Copy the link and run it through the helper, in single quotes:

```sh
../../helper/target/debug/keyseal run 'keyseal://sign?...'
```

The helper asks whether to trust `127.0.0.1:8787`, flagged as insecure, then shows the document and the certificates on the token. Choose one, such as `keyseal e2e rsa`, and enter the PIN `1234`. The page's status turns to completed and names the signed PDF, such as `out/3f1c...-0.pdf`.

### Without a browser

The same job runs from the terminal alone, with the helper headless. A headless helper can't choose between certificates, so the job names one with `expectedCertificateSha256`, the SHA-256 of the certificate, as [docs/integrating.md](integrating.md#3-create-jobs) recommends for every sign job. The reference server's `POST /jobs` takes the PDF as base64 and returns the link, and `KEYSEAL_HEADLESS_TRUST_ORIGIN` lets a headless helper accept this origin on first contact:

```sh
sha="$(openssl dgst -sha256 -r quickstart/token/rsa.der | cut -d' ' -f1)"
job="$(jq -n --arg pdf "$(base64 -w0 sample.pdf)" --arg sha "$sha" \
  '{documents: [{pdf: $pdf, signatureDetails: {reason: "Trying KeySeal"}}],
    title: "Quickstart", signer: "Test Signer", expectedCertificateSha256: $sha}' |
  curl -fsS -H 'Content-Type: application/json' --data @- http://127.0.0.1:8787/jobs)"
KEYSEAL_HEADLESS=1 KEYSEAL_PIN=1234 KEYSEAL_HEADLESS_TRUST_ORIGIN=http://127.0.0.1:8787 \
  ../../helper/target/debug/keyseal run "$(jq -r .link <<<"$job")"
curl -fsS "http://127.0.0.1:8787/jobs/$(jq -r .id <<<"$job")/status"
```

The helper prints the job and `Signed`, and the status is `completed` with the signed PDF's path in `outputs`.

## 5. Check the signed PDF

The reference server writes signed PDFs inside its container. Copy one out with the path the status gave, and have the service validate it:

```sh
docker compose cp reference-server:/app/examples/reference-server/out/<reference>-0.pdf signed.pdf
curl -fsS -H 'Authorization: Bearer quickstart-only-not-a-secret-0123456789' \
  --data-binary @signed.pdf http://127.0.0.1:8090/validate | jq
```

The report's `status` is `valid`, and its one signature is `intact` and `trusted`, signed by `keyseal e2e rsa` or whichever certificate you chose. A PDF viewer shows the signature too, as from an unknown signer, since your system doesn't trust the test CA.

## Clean up

```sh
docker compose down
rm -rf quickstart sample.pdf signed.pdf
```

## macOS and Windows

The quickstart has been run on Linux only. On the other systems, SoftHSM installs as below, the way the project's CI installs it for the helper's tests; the other steps are the same, with that module path for `module` and `KEYSEAL_PKCS11_MODULE`.

- **macOS:** `brew install softhsm opensc openssl@3`, and put Homebrew's OpenSSL first on the `PATH` for the token script, since the system's LibreSSL lacks options it uses: `export PATH="$(brew --prefix openssl@3)/bin:$PATH"`. The module is `$(brew --prefix softhsm)/lib/softhsm/libsofthsm2.so`. Docker Desktop provides Docker and Compose, and the helper needs no extra build dependencies.
- **Windows:** CI installs SoftHSM2 for Windows 2.5.0 with an administrative install of the MSI that Chocolatey's `softhsm.install` downloads, into `C:\SoftHSM2`, and OpenSC with `choco install opensc`; the module is `C:\SoftHSM2\lib\softhsm2-x64.dll`, and `C:\SoftHSM2\bin`, `C:\SoftHSM2\lib` and OpenSC's `tools` directory go on the `PATH`. See the `SoftHSM (Windows)` step in [.github/workflows/checks.yml](../.github/workflows/checks.yml). The token script is a bash script, and hasn't been run on Windows.

## Next

- [docs/integrating.md](integrating.md) adds token signing to your own application.
- [examples/reference-server/README.md](../examples/reference-server/README.md) lists the reference server's endpoints, which the quickstart uses.
- With a real token, run the reference server against the service with the CA your signers' certificates chain to, and use a released helper: it finds the token's driver itself.
