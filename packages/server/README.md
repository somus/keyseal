# @keyseal/server

Server side of the KeySeal job protocol ([spec/protocol-v1.md](../../spec/protocol-v1.md)), written against the Fetch API `Request` and `Response`, so it runs on Bun, Node 22+ and Cloudflare Workers. It serves the manifest and the job endpoint the helper talks to, creates jobs, and calls the signing service in [`service/`](../../service). You supply an adapter for job storage, blobs and the completion callback.

## Use

```ts
import { createKeySeal, ServiceClient } from "@keyseal/server";

const keyseal = createKeySeal({
  adapter, // see below
  service: new ServiceClient({
    url: process.env.SIGNING_SERVICE_URL,
    token: process.env.SIGNING_SERVICE_TOKEN,
  }),
  origin: "https://dash.example.org", // https on a domain name; see allowInsecureOrigin below
  basePath: "/api/keyseal", // job URLs are <origin><basePath>/v1/jobs/<token>
  minHelperVersion: "1.0.0", // optional: older helpers get 426
  branding: {
    // optional: served as /.well-known/keyseal.json
    name: "Example Trust",
    icon: "https://dash.example.org/keyseal-logo.png", // optional: PNG on the origin, at most 256 KiB
    accentColor: "#1f6feb", // optional
    translucent: false, // optional: opaque job windows instead of glass on macOS
  },
  rateLimit: (request) => true, // optional: return false to answer 429
});

// Mount it at your edge; it answers 404 for anything that isn't its route.
const response = await keyseal.handle(request);

// Create a job for the signed-in user and hand the link to the page.
const { id, link } = await keyseal.createSignJob({
  title: "Board resolution 2026/14",
  signer: "Asha Rao",
  documents: [
    {
      pdf, // with an empty signature field, see the service's /prepare
      fieldName: "Signature1",
      signatureDetails: { reason: "Approved as Director", location: "Mumbai" }, // optional
      // title: "...", // required when there are several documents
      // stampStyle: "...", // optional: the service's stamp style
    },
  ],
  expectedCertificateSha256, // recommended
  certificatePolicy: { policyOids: ["2.16.356.100.2.3"] }, // optional, see Certificates
  rsaPadding: "pss", // optional; PKCS#1 v1.5 by default
  reference: "resolution-14", // yours, handed back with the job
});

// The page polls your backend, which asks by id:
const status = await keyseal.status(id); // { state, message?, kind, reference, expiresAt }
```

`createSignJob` and `createEnrolJob` return `{ id, token, link, jobUrl }`. `id` is the SHA-256 of the job token, the key the adapter stores the job under; keep it to ask `status`. The token is the helper's credential for the job endpoint and is already inside `link` and `jobUrl`; nothing on your server needs it again, so discard it once the link is handed to the page.

`documents` holds 1 to 20 PDFs, signed together after one PIN entry (spec section 8.2). Each entry has its own `pdf` (at most 25 MiB), `fieldName`, optional `title` (1 to 200 characters), `stampStyle` and `signatureDetails`; the job-wide options (`signer`, the certificate rules, `digestAlgorithm`, `rsaPadding`) apply to all of them. A job with one document gives it the job's `title` unless it has its own; with several, every entry needs one, and the job's `title` describes the batch. The PDFs of one job may total at most 240 MiB (`MAX_JOB_PDF_BYTES`), which keeps the prepared documents within the 256 MiB the helper downloads per job. Job creation throws a `TypeError` naming the entry, such as `documents[2].title`, for anything else.

`signatureDetails` takes `reason`, `location` and `contactInfo`, each optional. They are written into the signature dictionary as `/Reason`, `/Location` and `/ContactInfo`, which PDF viewers show in their signature panel, and the service's built-in stamp shows the reason. Each is trimmed and must then be 1 to 200 characters without control characters. The job stores them on its document and round 1 passes them to the service's `/sign/start`; the helper never sees them.

A batch is all or nothing. Round 1 prepares every document with the service and stores one state per document; if any fails, it keeps none. Round 2 verifies every signature over its document's SignedAttributes with the certificate's key (through `certificateInspector.verify`) before the service finishes any document, and one that doesn't verify fails the job with 422. Every document is then finished in memory, and only when all are does `onCompleted` run, so a refusal, a service failure or a lease takeover mid-batch never hands over part of one.

`createEnrolJob({ title, signer, expectedCertificateSha256?, certificatePolicy?, reference? })` captures a certificate without signing.

`createKeySeal` throws unless `origin` is a bare `https` origin whose host is a domain name, not an IP address or `localhost` (spec section 4). For development and CI, `allowInsecureOrigin: true` also accepts `http://localhost` and `http://127.0.0.1` on any port, the origins the helper allows under `KEYSEAL_ALLOW_INSECURE_ORIGINS=1`. `title`, `signer`, `branding.name` and failure messages are measured in Unicode code points.

`status(id)` returns null for a malformed or unknown id. Otherwise it returns the job's `state` and, when it failed or expired, a `message` for the user, the shape `@keyseal/browser` expects (spec Appendix B).

## Adapter

```ts
interface Adapter {
  create(job: Job): Promise<void>;
  get(id: string): Promise<Job | null>;
  transition(id, expected: { state, leaseStartedAt }, patch): Promise<boolean>;
  expireOlderThan(cutoff: Date, leaseCutoff: Date): Promise<Job[]>;
  putBlob(key: string, bytes: Uint8Array): Promise<void>;
  getBlob(key: string): Promise<Uint8Array | null>;
  deleteBlob(key: string): Promise<void>;
  onCompleted(job: Job, result: CompletedResult): Promise<void>;
  onFailed?(job: Job, failure: JobFailure): Promise<void>;
}
```

- `id` is the SHA-256 of the job token; the raw token is never stored, and the claim nonce is stored hashed too.
- `transition` must be atomic: apply the patch only if the job's state and `leaseStartedAt` (compared by time) still equal `expected`. In SQL this is one `UPDATE ... WHERE id = ? AND state = ? AND lease_started_at IS NOT DISTINCT FROM ?`.
- `expireOlderThan` runs when a job is created; it marks open jobs created before `cutoff` `expired` and returns them so their blobs are deleted. It must skip jobs whose `leaseStartedAt` is at or after `leaseCutoff`, since a request holding a live settle lease may still finish.
- Blobs hold each document's PDF until round 1 (`<id>/pdf/<index>`), then the signing service's state for each document until the job ends (`<stateKey>/<index>`), one blob per document of up to about 35 MB, and about 330 MB for the largest job. A store with a smaller object limit still fits, since no blob holds more than one document.
- `onCompleted` receives the signed PDFs as `result.pdfs`, in the order of `job.documents`, and the certificate facts (sign), or the certificate facts (enrol). The PDFs of a batch arrive together, all of them or none, and round 2 holds them all in memory at once. It runs before the job is marked completed: if it throws, the job stays open and the helper can retry. Keep it idempotent on `job.id`, since a retry that takes over a lapsed settle lease may call it again. To refuse the result, for example a certificate not in the signer's name, throw `new JobRefused(message)`: the job fails with `message`, which the helper gets with a 422 and the page in `status`. Any other error answers 500 and leaves the job as it was.
- `onFailed`, if set, receives the job and `{ message, reportedBy }` when the job fails: `reportedBy` is `helper` for a failure report and `server` for a refused certificate or signature, a `JobRefused`, or an outdated helper (426). Expiry does not call it. Like `onCompleted` it runs under the settle lease, before the job is marked failed, and may run again after a lease takeover; an error from it is logged and the job fails anyway.

`createMemoryAdapter({ onCompleted, onFailed? })` keeps everything in process memory, for tests and the reference server.

## Certificates

Certificates are parsed, and round 2's signatures verified, with `node:crypto` by default (Node, Bun, Workers with `nodejs_compat`). Pass `certificateInspector` to use another parser; its `verify` checks a signature with the certificate's key as spec section 11.1 encodes it. Sign round 1 and enrol accept RSA, P-256 and P-384 keys that are valid now, match `expectedCertificateSha256` if set, and chain to a root the signing service trusts; anything else is refused with 422 and fails the job.

`certificatePolicy` (spec section 8.2) limits a job to certificates with at least one of `policyOids` in their certificatePolicies extension, an issuer CN in `issuerCommonNames`, and the subject O `subjectOrganization`. Every member given must hold, and strings compare exactly. Job creation throws a `TypeError` for an empty policy, a list outside 1 to 16 entries, an OID that isn't dotted decimal or is over 128 characters, or a name outside 1 to 200 characters. The issuer CN is read from the certificate's issuer name: the signing service's chain check only passes when that name is the subject of the CA certificate whose signature it verified, so a certificate cannot claim an issuer it doesn't chain to. The inspector reports `policyOids`, `issuerCommonName` and `subjectOrganization` (null when the name has none or several), and they reach `onCompleted` in the certificate facts.

## Develop

```sh
bun test packages/server
bun run --filter @keyseal/server build
scripts/make-test-certificates.sh   # regenerates test/fixtures, with the RSA, P-256 and P-384 keys
```
