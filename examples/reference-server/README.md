# reference-server

A minimal integrator backend: `@keyseal/server` with the in-memory adapter, wired to a running signing service. It serves a one-page UI that creates a sign job for one or more uploaded PDFs, opens the `keyseal://` link and polls the job, and it writes each signed PDF to `./out/<reference>-<index>.pdf`, the index 0-based in the job's order. The end-to-end CI drives it headless through the same endpoints.

## Run

Start the signing service (see [service/README.md](../../service/README.md)), then:

```sh
bun install
cd examples/reference-server
SIGNING_SERVICE_URL=http://127.0.0.1:8090 \
SIGNING_SERVICE_TOKEN=<the service's token> \
KEYSEAL_ORIGIN=http://127.0.0.1:8787 \
bun run start
```

Open `http://127.0.0.1:8787/`. A helper only accepts an `http://localhost` or `http://127.0.0.1` origin when it runs with `KEYSEAL_ALLOW_INSECURE_ORIGINS=1`, and the server passes `allowInsecureOrigin: true` to accept those origins; anywhere else, put the server behind HTTPS and set `KEYSEAL_ORIGIN` to that origin.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIGNING_SERVICE_URL` | required | Base URL of the signing service |
| `SIGNING_SERVICE_TOKEN` | required | The service's bearer token |
| `KEYSEAL_ORIGIN` | `http://localhost:$PORT` | Origin of the job URLs in `keyseal://` links |
| `PORT` | `8787` | Listen port |
| `KEYSEAL_MIN_HELPER_VERSION` | none | Refuse older helpers with 426 |

## Endpoints

- `POST /jobs` with `{ "documents": [{ "pdf": "<base64>", "title"?, "fieldName"?, "signatureDetails"?: { "reason"?, "location"?, "contactInfo"? } }], "title"?, "signer"?, "expectedCertificateSha256"?, "certificatePolicy"?, "rsaPadding"?: "pkcs1" | "pss" }` creates a sign job for 1 to 20 PDFs, signed together, and returns `{ id, link, jobUrl, reference }`. Every document needs a `title` when there are several. Without `fieldName`, the server adds an empty signature field on the last page of that PDF through the service's `/prepare`.
- `POST /enrol-jobs` with `{ "title"?, "signer"?, "expectedCertificateSha256"?, "certificatePolicy"? }` creates an enrol job and returns the same shape.
- `GET /jobs/<id>/status` returns `{ state, message?, kind, reference, expiresAt, outputs }`, where `outputs` lists the signed PDFs' paths in the job's order once the job is `completed`, and is null before.
- `/.well-known/keyseal.json` and `/v1/jobs/...` are the protocol endpoints served by `@keyseal/server`.
