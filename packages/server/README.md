# @keyseal/server

Server side of the KeySeal job protocol ([spec/protocol-v1.md](../../spec/protocol-v1.md)), written against the Fetch API `Request` and `Response`, and tested on Bun and Node 22+. Cloudflare Workers is untested and suits small documents at most: the server holds a job's PDFs in memory, as bytes and as base64 JSON, so a 25 MiB document needs several times its size, more than a Workers isolate's 128 MB. It serves the manifest and the job endpoint the helper talks to, creates jobs, and calls the signing service in [`service/`](../../service). You supply an adapter for job storage, blobs and the completion callback.

This README is the package's API reference. [docs/integrating.md](../../docs/integrating.md) walks through an integration step by step, and [docs/production.md](../../docs/production.md) covers deployment, failures and upgrades.

## Install

```sh
npm install @keyseal/server
```

It needs Node 22 or later, or Bun. The type declarations use `Uint8Array<ArrayBuffer>`, so type-checking against them needs TypeScript 5.7 or later.

## Use

```ts
import { createKeySeal, ServiceClient } from "@keyseal/server";

const keyseal = createKeySeal({
  adapter, // see Adapter below
  service: new ServiceClient({
    url: process.env.SIGNING_SERVICE_URL,
    token: process.env.SIGNING_SERVICE_TOKEN,
  }),
  origin: "https://dash.example.org", // https on a domain name; see allowInsecureOrigin below
  basePath: "/api/keyseal", // job URLs are <origin><basePath>/v1/jobs/<token>
  minHelperVersion: "0.3.0", // optional: older helpers get 426
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
      pdf, // with an empty signature field, see ServiceClient.prepare
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

## Options

`createKeySeal(options)` returns the `KeySeal` object below. It throws a `TypeError` naming the option for any value outside these rules.

| Option | Default | Meaning |
| --- | --- | --- |
| `adapter` | required | Job storage, blobs and the completion callback ([Adapter](#adapter)). |
| `service` | required | A `ServiceClient`, or any object with its `certificate`, `signStart` and `signFinish` methods (the `SigningService` type), such as a proxy that adds retries or a test double ([Signing service client](#signing-service-client)). |
| `origin` | required | Scheme, host and port of the job URLs. A bare `https` origin whose host is a domain name, not an IP address or `localhost` (spec section 4), with no path or trailing slash. |
| `basePath` | `""` | Path the job endpoint is mounted under: empty, or `/`-separated segments of letters, digits, `.`, `_`, `~` and `-`, none of them `.` or `..`. The manifest is always at the origin's root. |
| `allowInsecureOrigin` | `false` | For development and CI: also accepts `http://localhost` and `http://127.0.0.1` on any port, the origins the helper allows under `KEYSEAL_ALLOW_INSECURE_ORIGINS=1`. |
| `minHelperVersion` | none | SemVer version. Job endpoint requests from older helpers, or without a parseable `X-KeySeal-Version`, get 426 ([Failures](#failures)). |
| `branding` | none | The manifest. `name` is 1 to 64 characters; `icon` an absolute URL on `origin` of a PNG of at most 256 KiB; `accentColor` `#rrggbb`; `translucent` a boolean. Without it, `/.well-known/keyseal.json` is a 404 and the helper shows no branding. [docs/integrating.md](../../docs/integrating.md#branding) shows where each appears. |
| `rateLimit` | none | `(request) => boolean \| Promise<boolean>`, called first for every job endpoint request; `false` answers 429. The spec asks for a limit per client address. |
| `certificateInspector` | `nodeCertificateInspector` | X.509 parsing and signature checks ([Certificates](#certificates)). |
| `now` | `() => new Date()` | The clock, for tests. |

`title`, `signer`, `branding.name` and failure messages are measured in Unicode code points.

The `KeySeal` object:

- `handle(request)` answers `GET /.well-known/keyseal.json` and the job endpoint under `basePath`, and 404 for anything else. The helper calls these routes without your session, so they authenticate by the job token alone; route them outside your own authentication. An error from the adapter, or any other unexpected error, is logged as `keyseal: job request failed` with the error, which names the job by its id and never by its token, and answered 500.
- `createSignJob(input)` and `createEnrolJob(input)` create jobs ([Jobs](#jobs)).
- `status(id)` returns `null` for a malformed or unknown id, and otherwise `{ state, message?, kind, reference, expiresAt }`. `state` is `expired` from the moment the job's 15 minutes are up, whether or not the adapter has recorded it, and `message`, present when the job failed or expired, is written for the user. `{ state, message }` is the shape `@keyseal/browser` expects (spec Appendix B), so the object can be sent to the page as JSON.
- `manifest()` returns the manifest response `handle` serves. It carries `minHelperVersion` when that option is set, so a helper can tell the signer to update before it claims a job; without `branding` there is no manifest, and the 426 is the only check.
- `sweep()` expires the jobs past their 15 minutes and deletes their blobs, and deletes the blobs of jobs that ended or no longer exist, such as those whose deletion failed when the job completed. Creating a job expires old jobs too, so call `sweep()` from a scheduler, every few minutes, to clean up while no jobs are created. It rejects if the adapter does; the next run picks up where it stopped.

## Jobs

`createSignJob` and `createEnrolJob` return `{ id, token, link, jobUrl }`. `id` is the SHA-256 of the job token, the key the adapter stores the job under; keep it to ask `status`. The token is the helper's credential for the job endpoint and is already inside `link` and `jobUrl`; nothing on your server needs it again, so discard it once the link is handed to the page, and don't log it. They throw an `InvalidJobInput` for input that breaks one of the [limits](#limits), with a message that names the member, such as `documents[2].title`; answer your own caller with a 400 for that error only. `InvalidJobInput` extends `TypeError`, but so is a failed `fetch` in an adapter, so test for the class, not for `TypeError`. Errors from the adapter propagate unchanged.

`documents` holds 1 to 20 PDFs, signed together after one PIN entry (spec section 8.2). Each entry has its own `pdf`, `fieldName` (the empty signature field to sign in), optional `title`, `stampStyle` and `signatureDetails`; the job-wide options (`signer`, the certificate rules, `digestAlgorithm`, `rsaPadding`) apply to all of them. A job with one document gives it the job's `title` unless it has its own; with several, every entry needs one, and the job's `title` describes the batch.

`signatureDetails` takes `reason`, `location` and `contactInfo`, each optional. They are written into the signature dictionary as `/Reason`, `/Location` and `/ContactInfo`, which PDF viewers show in their signature panel, and the service's built-in stamp shows the reason. Each is trimmed and must then be 1 to 200 characters without control characters. The job stores them on its document and round 1 passes them to the service's `/sign/start`; the helper never sees them.

`rsaPadding: "pss"` makes RSA keys sign with RSA-PSS instead of PKCS#1 v1.5; ECDSA keys ignore it. `digestAlgorithm` (`sha256` or `sha384`) announces the digest in the job description, and a certificate whose key signs with the other one is refused (P-384 and brainpoolP384r1 keys sign SHA-384, every other key SHA-256). Leave it out unless you need one digest. `reference` is any string of yours; it is stored as given and handed back on the job and in `status`.

A batch is all or nothing. Round 1 prepares every document with the service and stores one state per document; if any fails, it keeps none. Round 2 verifies every signature over its document's SignedAttributes with the certificate's key (through `certificateInspector.verify`) before the service finishes any document, and one that doesn't verify fails the job with 422. It then asks the service again whether the certificate is trusted, failing the job with 422 if it no longer is. Every document is then finished in memory, up to four at a time, and only when all are does `onCompleted` run, so a refusal, a service failure or a lease takeover mid-batch never hands over part of one.

`createEnrolJob({ title, signer, expectedCertificateSha256?, certificatePolicy?, reference? })` captures a certificate without signing a document. The helper proves it holds the certificate's key by signing a message bound to the job URL, the claim nonce and the certificate (spec section 8.6), and the server verifies it, through `certificateInspector.verify`, after the certificate checks: a proof that doesn't verify is refused with 422 and fails the job, and a submission without one gets 426 with the higher of `minHelperVersion` and 0.5.0, the first helper that sends it, and fails the job. So a certificate copied out of a signed PDF can't be enrolled, but the proof doesn't show who the person at the helper is ([docs/integrating.md](../../docs/integrating.md#3-create-jobs)); use enrolment to learn which certificate to pass as `expectedCertificateSha256` to the user's later sign jobs.

## Limits

Check input against these before creating a job, so that you can tell your user what is wrong. The exported constants:

| Constant | Value | Limit |
| --- | --- | --- |
| `MAX_DOCUMENTS` | 20 | Documents in one sign job. |
| `MAX_PDF_BYTES` | 26214400 (25 MiB) | Each PDF. Job creation refuses a larger one, and `ServiceClient.prepare` and `signStart` throw a `ServiceError` with status 413 before sending it, as the service refuses it. |
| `MAX_JOB_PDF_BYTES` | 251658240 (240 MiB) | The PDFs of one job together, which keeps the prepared documents within the 256 MiB the helper downloads per job. |
| `MAX_BODY_BYTES` | 262144 (256 KiB) | The largest request body the job endpoint reads from the helper; a larger one is a 413. A proxy in front of the job endpoint must allow it. |
| `JOB_TTL_MS` | 900000 (15 minutes) | A job's lifetime from creation, whatever its state. |
| `SETTLE_LEASE_MS` | 300000 (5 minutes) | How long one request may hold a job while it settles it, before a repeated request may take it over (spec section 9.3). |

The other input limits, each refused with `InvalidJobInput`:

- `title`, `signer` and each document's `title`: 1 to 200 characters.
- `fieldName`: 1 to 64 letters, digits or underscores.
- `stampStyle`: 1 to 64 characters, a name the service knows; an unknown one fails the job in round 1.
- `signatureDetails` members: 1 to 200 characters after trimming, without control characters.
- `expectedCertificateSha256`: 64 hex characters, either case.
- `certificatePolicy`: see [Certificates](#certificates).
- `pdf`: a `Uint8Array`.

## Signing service client

`new ServiceClient({ url, token, fetch?, timeoutMs? })` makes typed calls to the signing service with its bearer token. `url` is the service's base URL, such as `http://signing:8080`, and `token` its `SIGNING_SERVICE_TOKEN`. `fetch` replaces the global `fetch`, and `timeoutMs`, 60000 by default, bounds each request, the response body included. The service's routes and its report are in [service/README.md](../../service/README.md).

| Method | Service route | Returns |
| --- | --- | --- |
| `prepare(pdf, fields)` | `/prepare` | The PDF with empty signature fields added, as one incremental update. Each field is `{ name, page, box }`: `name` 1 to 64 letters, digits or underscores, unique; `page` 0-based, negative counting from the last page (`-1` is the last); `box` `[x1, y1, x2, y2]` in PDF points from the page's lower-left corner. Up to 20 fields. |
| `certificate({ certificate, chain, keyUsage? })` | `/certificate` | `{ trusted, revocationChecked }` for a base64 DER certificate and chain. |
| `signStart(input)` | `/sign/start` | What the token signs, used by the job endpoint. |
| `signFinish({ state, signature })` | `/sign/finish` | The signed PDF, used by the job endpoint. |
| `validate(pdf, base?, keyUsage?)` | `/validate` | The validation report. `base` is the byte length of the copy the signer was given, for `changesSinceBase`; `keyUsage` as the job's. |

Every method throws a `ServiceError` on failure, with the service's `detail` as its message when it sent one, and a `status`:

- `400` or `422`: the service refused the input. `prepare` gets 422 for a PDF no signature can be added to, an encrypted one (even one that opens without a password) or one certified with no changes allowed, and for a PDF it can't read or a page it doesn't have; the message says which.
- `413`: the PDF is larger than `MAX_PDF_BYTES`.
- `401`: the token doesn't match the service's.
- `502`: the service's answer was larger than 64 MiB, or not the JSON that `certificate` or `signStart` expects.
- `503`: no timestamp authority answered (`/sign/finish`), and `504` a certificate check that ran past 45 seconds.
- `0`: the service couldn't be reached, or the request timed out.

In a job, a `ServiceError` with status 400 or 422 fails the job with its message, and any other leaves the job as it was and answers the helper 502 ([Failures](#failures)). A replacement `service` throws the same way; any other error answers 500.

## Failures

A job ends `failed` with a message for the user, which `status` returns and `onFailed` receives with `reportedBy`. The server refuses with 422 and fails the job, `reportedBy: "server"`, for:

| Cause | Message |
| --- | --- |
| The certificate isn't X.509 DER | The certificate could not be read. |
| Its key isn't RSA, P-256, P-384 or brainpool | The certificate's key is not supported. Use an RSA, P-256, P-384 or brainpool certificate. |
| Outside its validity period | The certificate is not valid now. |
| Not `expectedCertificateSha256` | This is not the certificate this job expects. Use the one registered for you. |
| Fails `certificatePolicy`, or its key usage | This certificate is not one this job accepts. Use a certificate of the kind the job asks for. |
| Its digest isn't the job's `digestAlgorithm` | The certificate's key does not match the digest this job announced. |
| The service doesn't trust it, in either round | The certificate is not from a trusted certifying authority, or may not sign. |
| A signature doesn't verify | The signature doesn't match the certificate: was the right token used? |
| An enrol proof doesn't verify | The proof doesn't match the certificate: was the right token used? |
| The service refused with 400 or 422 | The service's message, up to 500 characters, such as an encrypted PDF or an unknown stamp style. |
| `onCompleted` threw `JobRefused` | Its message. |

A helper below `minHelperVersion`, or an enrolment without a proof, gets 426 and fails the job with "Update the signing helper, then try again." when the job is pending or the request carries the claim nonce (spec section 7.3); the helper then checks for its update at once.

The helper reports every other failure itself, `reportedBy: "helper"`, with a message it writes: the signer cancelled, no token, driver or acceptable certificate was found, the PIN is locked, a document failed its check, or signing failed on the token. It also reports a failure when the job endpoint answers it with an error, including the 502 for a signing service outage and the 500 for an adapter error, so with the current helper those end the job as `failed` too, with a message that quotes your server's.

An expired job has `state: "expired"` and the message "The signing link expired. Start again."; `onFailed` isn't called for it. Every failed or expired job is final: start a new one. [docs/production.md](../../docs/production.md#handling-failures) says what to show and what to monitor.

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
  listBlobs(): Promise<string[]>;
  onCompleted(job: Job, result: CompletedResult): Promise<void>;
  onFailed?(job: Job, failure: JobFailure): Promise<void>;
}
```

- `id` is the SHA-256 of the job token; the raw token is never stored, and the claim nonce is stored hashed too.
- `get` returns the job as `create` stored it and `transition` changed it, with `createdAt` and `leaseStartedAt` as `Date`s, or `null`.
- `transition` must be atomic: apply the patch only if the job's state and `leaseStartedAt` (compared by time) still equal `expected`. In SQL this is one `UPDATE ... WHERE id = ? AND state = ? AND lease_started_at IS NOT DISTINCT FROM ?`.
- `leaseStartedAt` must keep millisecond precision. The server releases a lease by comparing against the `Date` it took the lease with, so a column that drops milliseconds, such as MySQL `DATETIME` without a fractional part, makes every settle's compare-and-swap fail and no job can finish. Use `DATETIME(3)`, Postgres `timestamptz`, or an integer of milliseconds.
- `expireOlderThan` runs when a job is created and in `sweep()`; it marks open jobs (`pending`, `claimed`, `prepared`) created before `cutoff` `expired` and returns them so their blobs are deleted. It must skip jobs whose `leaseStartedAt` is at or after `leaseCutoff`, since a request holding a live settle lease may still finish. It must be one atomic update, such as `UPDATE ... SET state = 'expired' WHERE state IN (...) AND created_at < ? AND (lease_started_at IS NULL OR lease_started_at < ?) RETURNING ...`: reading the jobs first and then writing them lets a request take the lease in between and have its job expired under it, and lets two concurrent job creations return the same job. The server uses the returned jobs' `id`, `documents` and `stateKey`.
- Blobs hold each document's PDF until round 1 (`<id>/pdf/<index>`), then the signing service's state for each document until the job ends (`<stateKey>/<index>`), one blob per document of up to about 35 MB, and about 330 MB for the largest job. A store with a smaller object limit still fits, since no blob holds more than one document. `deleteBlob` of a missing key is not an error. `listBlobs` returns the key of every blob stored with `putBlob` and not yet deleted; `sweep()` reads the job id before each key's first `/` and deletes the blobs of jobs that ended or are missing. It leaves any key that doesn't start with a job id, so a store shared with other data is safe, but a prefix of its own is simpler.
- `onCompleted` receives the signed PDFs as `result.pdfs`, in the order of `job.documents`, and the certificate facts (sign), or the certificate facts (enrol). `certificate.revocationChecked` is false when the signing service trusted the certificate without revocation data, as it does by default (see the service's README); decide whether to accept that. The PDFs of a batch arrive together, all of them or none, and round 2 holds them all in memory at once. It runs before the job is marked completed: if it throws, the job stays open and the request answers 500. Keep it idempotent on `job.id`, since a retry that takes over a lapsed settle lease may call it again. To refuse the result, for example a certificate not in the signer's name, throw `new JobRefused(message)`: the job fails with `message`, which the helper gets with a 422 and the page in `status`.
- `onFailed`, if set, receives the job and `{ message, reportedBy }` when the job fails ([Failures](#failures)). Expiry does not call it. Like `onCompleted` it runs under the settle lease, before the job is marked failed, and may run again after a lease takeover; an error from it is logged and the job fails anyway.

`createMemoryAdapter({ onCompleted, onFailed? })` keeps everything in process memory, for tests and the reference server. Its `jobs` and `blobs` maps are readable for assertions. It loses every job on restart and isn't shared between processes, so it doesn't suit production.

### Conformance suite

`@keyseal/server/testing` checks an adapter against the invariants above: a job round-trips unchanged with its `Date` fields as `Date`s, `leaseStartedAt` keeps milliseconds, `transition` applies its patch only on a matching state and lease and lets exactly one of several concurrent callers win, `expireOlderThan` expires exactly the open, unleased jobs before the cutoff and stays atomic against concurrent expiry and lease takeover, and blobs round-trip, overwrite, delete and are listed until deleted. It has no test-framework dependency, so it runs under Bun, Node and vitest alike.

```ts
import { adapterConformanceChecks, runAdapterConformance } from "@keyseal/server/testing";

// One test per check, with any runner that takes a name and an async function:
for (const check of adapterConformanceChecks(() => createMyAdapter())) {
  test(check.name, check.run);
}

// Or all in turn, throwing an AdapterConformanceError that names the first failed check:
await runAdapterConformance(() => createMyAdapter());
```

`makeAdapter` is called once per check. The checks write jobs dated 2001 under random ids and blobs under those ids, and look only at what they wrote, so they never expire a live job; still, point them at a disposable store, since they leave their rows behind. The concurrency checks start their calls together with `Promise.all`, so they catch a read-then-write implementation but cannot prove an adapter atomic. A failed check throws an `AdapterConformanceError`, whose `check` is the check's name.

## Certificates

Certificates are parsed, and round 2's signatures verified, with `node:crypto` by default (`nodeCertificateInspector`; Node, Bun, Workers with `nodejs_compat`). Pass `certificateInspector` to use another parser: its `inspect(der)` returns an `InspectedCertificate` or null, and its `verify` checks a signature with the certificate's key as spec section 11.1 encodes it. Brainpool keys are read from the certificate's DER and their signatures checked in TypeScript, since BoringSSL, behind `node:crypto` in Bun and Workers, lacks those curves. Sign round 1 and enrol accept RSA, P-256, P-384, brainpoolP256r1 and brainpoolP384r1 keys that are valid now, match `expectedCertificateSha256` if set, and chain to a root the signing service trusts with the job's key usage; anything else is refused with 422 and fails the job.

`certificatePolicy` (spec section 8.2) limits a job to certificates with at least one of `policyOids` in their certificatePolicies extension, an issuer CN in `issuerCommonNames`, and the subject O `subjectOrganization`, and sets the key usage with `keyUsage`: `"nonRepudiation"` (the default, also for jobs without a policy) needs the nonRepudiation KeyUsage bit, `"digitalSignature"` accepts digitalSignature or nonRepudiation, and a certificate without KeyUsage or a CA certificate never qualifies. Every member given must hold, a policy of only `keyUsage` is valid, and strings compare exactly. The job's key usage goes to the signing service's `/certificate` check in both rounds, and `ServiceClient.validate(pdf, base, keyUsage)` passes one to `/validate`. Job creation throws an `InvalidJobInput` for an empty policy, a `keyUsage` other than those two, a list outside 1 to 16 entries, an OID that isn't dotted decimal or is over 128 characters, or a name outside 1 to 200 characters. The issuer CN is read from the certificate's issuer name: the signing service's chain check only passes when that name is the subject of the CA certificate whose signature it verified, so a certificate cannot claim an issuer it doesn't chain to. The inspector reports `policyOids`, `issuerCommonName`, `subjectOrganization` (null when the name has none or several), `keyUsage` (the digitalSignature and nonRepudiation bits asserted, null without the extension) and `ca`, and they reach `onCompleted` in the certificate facts, with `der`, `chain`, `sha256`, `subject`, `subjectCommonName`, `issuer`, `serialNumber` (uppercase hex), `notBefore`, `notAfter`, `key` and `revocationChecked`.

## Develop

```sh
bun test packages/server
bun run --filter @keyseal/server build
scripts/make-test-certificates.sh   # regenerates test/fixtures, with the RSA, P-256 and P-384 keys and brainpool signatures
scripts/ci/node-smoke.sh            # packs both packages and imports them under Node
```

The `@keyseal/source` export condition points at `src/`, which the reference server runs with `bun --conditions=@keyseal/source` and type-checks with `customConditions`, so it needs no build. The package publishes `src` beside `dist`, so the condition resolves for consumers too; without it they get `dist`.
