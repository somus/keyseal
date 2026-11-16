# Running KeySeal in production

This page covers what an integration needs once it works: where each piece runs, its secrets, proxies, storage, logs and monitoring, upgrades, and what to do when a job fails. It assumes the integration from [integrating.md](integrating.md). Reference detail stays in the package and service READMEs, which this page links to.

## Topology

```
 signer's browser ──(your API, your session)──> your backend ──(private network)──> signing service
                                                   ▲   │                               not public
 keyseal helper ──(HTTPS, job token, public)───────┘   └──> your job store and blob store
```

- **The job endpoint and the manifest are public.** The helper reaches `<origin>/.well-known/keyseal.json` and `<origin><basePath>/v1/jobs/...` directly from the signer's computer, without your session, so route both to `keyseal.handle` outside your own authentication. The origin must be HTTPS on a domain name that resolves to a public address: the helper refuses IP literals, `localhost` and private, loopback and link-local addresses on every connection, doesn't follow cross-origin redirects, and doesn't use a proxy for the job connection ([design.md](design.md#trust-model)). An intranet-only origin therefore doesn't work.
- **The signing service is private.** Only your backend talks to it. Publish its port to your backend's network only, never to the internet; it holds no signer keys, but anyone with its token can use it to prepare and finish signatures and to validate PDFs. Put TLS in front of it if the path between the two crosses a network you don't control.
- **Every backend instance shares one job store.** A job's requests may reach any instance, so the adapter must be backed by a shared database and blob store. `createMemoryAdapter` keeps jobs in one process and loses them on restart.

## Proxies and timeouts

Check every proxy, load balancer and serverless limit on both paths:

- **Helper to job endpoint.** Request bodies are at most 256 KiB (`MAX_BODY_BYTES`). Responses are small JSON, except the document downloads, which serve each prepared PDF, up to the 25 MiB of its original plus what preparing adds; the helper accepts up to 64 MiB per document and 256 MiB per job, and waits 60 seconds per download. It waits 90 seconds for every other request. Rounds 1 and 2 call the signing service once per document in turn, and round 2 asks a timestamp authority once per document, so give the job endpoint's routes a read timeout of at least 90 seconds.
- **Backend to signing service.** JSON request bodies reach 60 MiB plus 16 KiB, a PDF in base64 with its signing state; answers are capped at 64 MiB. `ServiceClient` waits 60 seconds per request (`timeoutMs`), and the service stops `/validate`, `/certificate`, `/finalize` and `/retimestamp` at 45 seconds.
- **Memory.** A job's PDFs are held in memory several times over, as bytes and as base64 JSON, and round 2 holds every signed PDF of a batch at once. Size the backend for your largest batch, up to the 240 MiB of PDF a job may carry ([limits](../packages/server/README.md#limits)).

## Secrets

**The service token.** `SIGNING_SERVICE_TOKEN` is the one secret the backend and the service share. The service refuses to start with a token shorter than 32 characters or with fewer than 10 distinct ones; `openssl rand -base64 32` makes a good one. Keep it in your secret store, never in the page or in a `keyseal://` link. Rotating it has two effects. While the backend and the service disagree, every service call gets 401, which the job endpoint answers as an outage. And the signing state `/sign/start` returns carries a MAC keyed with the token, so a job prepared before the rotation fails at `/sign/finish` with a 422 and its signer starts again. Rotate when no job is waiting for a PIN, or accept those failures.

**Job tokens.** Each `keyseal://` link carries its job's token, the helper's credential. `@keyseal/server` stores only its SHA-256 and never logs it, but the token is the last path segment of every job endpoint request, so your access logs and your proxy's do record it unless you exclude or redact `<basePath>/v1/jobs/` paths. A token claims its job once, after which every request also needs the claim nonce only the claiming helper has, and every job expires within 15 minutes, which limits what a logged token is worth. Don't log the link your API returns to the page either.

**Job ids.** `createSignJob` returns an `id`, which your status route passes to `keyseal.status(id)`. It isn't a credential for the job endpoint, but the status carries your `reference` and the failure message, so serve it only to the user the job belongs to.

## Trust roots, timestamps and revocation

The service's environment is listed in [service/README.md](../service/README.md#environment). The decisions to make:

- **Trust roots.** The image trusts the CCA India roots and known intermediates. For another PKI, `SIGNING_TRUST_ROOTS_DIR` replaces them and `SIGNING_EXTRA_TRUST_ROOTS_DIR` adds to them. They are read at startup, so restart the service after changing them, and check `trustRoots` in `GET /health`. Only these roots make a signer `trusted`; the system's CA bundle counts for timestamp authorities' certificates, not for signers.
- **Timestamp authority.** Signatures are PAdES B-T, timestamped by DigiCert's free TSA over plain HTTP by default. An HTTPS TSA in `SIGNING_TSA_URL` closes the gap the service README describes, and a second authority belongs in the list only if its tokens are trusted wherever your PDFs are validated. With a TSA configured, every signature needs a timestamp, so a TSA outage stops signing (see [Monitoring](#monitoring)); `SIGNING_TSA_URL=none` signs without one, for testing.
- **Revocation.** With the default `SIGNING_ALLOW_FETCHING` off, the service fetches no revocation data, so it trusts a revoked certificate unless the PDF carries the data that revokes it, and `revocationChecked` is false in `onCompleted`. Turning fetching on needs outbound HTTP and HTTPS from the service to the CAs' public CRL and OCSP servers. Either way, decide in `onCompleted` whether to accept a certificate whose revocation status wasn't checked.
- **Long-term validation.** For signatures that must stay verifiable after the certificate expires, store the PDF from `onCompleted`, then send it to the service's `/finalize` for revocation data and a document timestamp (PAdES B-LTA), and to `/retimestamp` before that timestamp's certificate expires. `@keyseal/server` doesn't call these routes; call them over HTTP with the bearer token.
- **Stamp time zone.** The built-in stamp prints the date in the container's time zone, UTC unless `TZ` names one, such as `Asia/Kolkata`.

## Storage and cleanup

Run the [conformance suite](../packages/server/README.md#conformance-suite) against your adapter in your own tests, on the same database engine as production: it checks the atomic `transition` and `expireOlderThan` and the millisecond `leaseStartedAt` that the settle lease depends on. Blobs hold each PDF and then its signing state while a job is open, up to about 35 MB per document and about 330 MB for the largest job, and are deleted when the job ends.

Call `keyseal.sweep()` from a scheduler every few minutes. It expires old jobs and deletes their blobs, which creating a job also does, and it deletes the blobs of jobs that ended but whose deletion failed. Without it, a quiet deployment keeps expired jobs' PDFs until the next job is created.

`onCompleted` runs before the job is marked completed, and a request that takes over a lapsed settle lease may call it again for the same job, so store the signed PDFs durably, keyed by `job.id`, and make a second call for the same job a no-op.

## Rate limiting

Rate limit the job endpoint per client address, at your edge or with the `rateLimit` option of `createKeySeal`, which answers 429 when it returns false. A job takes a handful of requests: the manifest and its icon, the claim, round 1, a download per document, round 2 and perhaps a failure report. Token entropy makes guessing infeasible; the limit protects your backend and the signing service. Rate limit your own job creation route per user too, since each job holds up to 240 MiB in your blob store for 15 minutes.

## Logs

- **`@keyseal/server`** writes to `console.error`: `keyseal: job request failed` with the error for every job endpoint request answered 500, such as an adapter error or an `onCompleted` that threw, and `keyseal: onFailed failed for job <id>` when `onFailed` throws. It never logs a job token.
- **The signing service** logs to stderr as `LEVEL: logger: message`, beside uvicorn's own access log, at the level `SIGNING_LOG_LEVEL` sets. At `INFO` it records why `/certificate` refused a certificate; timestamp authorities that failed are warnings when another one answered and errors when none did, naming the hosts.
- **The helper** logs each step of a job to `keyseal.log` on the signer's computer, without the link or the PIN. For a signer's problem, ask for the diagnostics from its Settings window and the log ([signers.md](signers.md#getting-help)).

## Monitoring

- **`GET /health`** on the service says the process is up and how many trust roots it loaded; the image's `HEALTHCHECK` uses it. Use it for liveness and load balancing.
- **`GET /ready`** says whether a timestamp authority answered lately: 503 means signing fails until one does, while validation still works. Neither route needs the token. Alert on `/ready` and show your users that signing is unavailable, but don't take the service out of rotation on it: a TSA outage hits every instance at once ([service/README.md](../service/README.md#environment)).
- **Job outcomes.** Count jobs that complete, fail and expire. `onFailed` tells you who ended a job: many `reportedBy: "server"` failures point at your certificate rules, trust roots or service; a rise in helper failures quoting status 502 or 500 points at the service or your adapter; `Update the signing helper` failures mean signers are behind `minHelperVersion`. Jobs that expire while `pending` are signers who never got the helper started.
- **Errors.** Alert on the `keyseal: job request failed` log line and on 5xx answers from the job endpoint.

## Versions and upgrades

Each component is versioned and released on its own ([CHANGELOG.md](../CHANGELOG.md)), and all of them speak protocol version 1, which only adds optional members ([spec/README.md](../spec/README.md)). The end-to-end test runs the newest release of each together. Where to find it:

| Component | Newest release |
| --- | --- |
| Helper | [GitHub releases](https://github.com/somus/keyseal/releases/latest) |
| Signing service | the image tag in [integrating.md](integrating.md#1-run-the-signing-service) |
| `@keyseal/server` | [npm](https://www.npmjs.com/package/@keyseal/server) |
| `@keyseal/browser` | [npm](https://www.npmjs.com/package/@keyseal/browser) |

The dependencies between them that the changelog records: `@keyseal/server` 0.6.0 requires helper 0.5.0 or later for enrol jobs, and answers an older one with 426 on its own; `@keyseal/server` 0.2.0 and later need service 0.2.0 or later; and from 0.4.0 it sends the job's key usage to `/certificate`, which service 0.3.0 and later check. `@keyseal/browser` works with any `@keyseal/server`, since it reads only `state` and `message`. Run the current service with the current server package.

**A new helper release** needs nothing from you. The helper checks for an update at most once a day after a job, verifies the maintainers' signature and installs it on its next start. A few signers update by hand: a Mac user without an administrator account, and Linux installs from the deb or the tarball ([signers.md](signers.md#updates)).

**`minHelperVersion`** makes older helpers update before they can use your origin. A job endpoint request from an older helper gets 426, the job fails with "Update the signing helper, then try again.", the helper shows the version it needs and checks for its update at once, and the signer clicks Sign again once it is installed. With `branding` set, the manifest carries the minimum too, so a current helper says so before it claims the job. Raise it only for a helper fix or feature your signers need, and only once that release is published, since a minimum no release meets locks every signer out.

**Upgrading `@keyseal/server`.** Read its changelog section. A release that changes the adapter contract, as 0.5.0 added `listBlobs`, says so; rerun the conformance suite.

**Upgrading the service.** The `0.5` tag moves with patch releases; pin a full version or a digest for an image that can't change. The signing state between `/sign/start` and `/sign/finish` is opaque apart from its `output`, and its other members may change between versions, so upgrade when no job is waiting for its signer's PIN, or expect a job prepared before the upgrade to fail and its signer to start again.

## Handling failures

What each failure carries, with the exact messages the server writes, is in [packages/server/README.md](../packages/server/README.md#failures). What to do with them:

- **At job creation**, catch `InvalidJobInput` and answer your caller with its message as a 400; check sizes and counts against the [limits](../packages/server/README.md#limits) first so it rarely happens. `ServiceClient.prepare` throws a `ServiceError` with status 422 for a PDF no signature can be added to, an encrypted or no-changes-certified one, or one it can't read; show its message and ask for an unprotected copy. Any other `ServiceError` means the service is down or misconfigured: try again later.
- **While the page waits**, show the job's state and, once `onNotClaimed` fires, a "Didn't open? Download the helper" link beside it, never in its place ([integrating.md](integrating.md#4-start-the-helper-from-the-page)).
- **When the job fails or expires**, show `message` as plain text and offer to start again, which creates a new job: a failed or expired job is final. Don't parse the message; branch on `state` and `reportedBy`, since the helper's messages and the service's may change between releases.
- **When the helper refuses a certificate**, the signer usually used the wrong token or a certificate other than the enrolled one. After a certificate renewal, `expectedCertificateSha256` no longer matches: run an enrol job for the new certificate, check it, and pin it.
- **When the helper is too old**, the helper has already started its update; tell the signer to click Sign again after it installs, or to download it again from the links in [integrating.md](integrating.md#5-install-the-helper).
- **When the service or your store fails** mid-job, the job endpoint answers 502 or 500 and leaves the job as it was, and the current helper then reports the failure, so the page sees `failed` with a message quoting your server's answer. Check `/ready` and your logs before asking the signer to try again.

`watchJob` and `signWithHelper` reject, rather than resolve, when your status route throws, when the watch is aborted, and after `timeoutMs`, 15 minutes by default; treat those as "status unknown" and keep the job's own state as the truth ([packages/browser/README.md](../packages/browser/README.md#api)).

For signers' own problems, the token, its driver, the PIN, the security warnings on installing, send them to [signers.md](signers.md), and ask for the helper's diagnostics when they contact you.

## Before going live

- Serve the job endpoint over HTTPS on a public domain name. `allowInsecureOrigin` and the helper's `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` are for development only.
- If you send a Content-Security-Policy, allow `keyseal:` in `frame-src`. Development servers often send no CSP, so this only shows up in production.
- Try a first contact with the helper installed: leave its trust prompt open past five seconds and check that the page keeps the job's status on screen next to the download link.
- Keep the signing service off the public internet, with a strong token from your secret store.
- Give the job endpoint's routes a read timeout of at least 90 seconds and a body limit of at least 256 KiB, and keep job tokens out of your access logs.
- Pin `expectedCertificateSha256` on sign jobs, and set `certificatePolicy` where you can't pin yet.
- Pass `rateLimit` to `createKeySeal` if the job endpoint isn't rate limited at your edge.
- Make `onCompleted` idempotent on `job.id`: a retry after a lapsed settle lease may call it again.
- Run the adapter conformance suite against your production database engine, and schedule `keyseal.sweep()`.
- Alert on the service's `/ready` and on 5xx answers from the job endpoint.
- Decide whether to accept certificates with `revocationChecked` false, and whether to turn on `SIGNING_ALLOW_FETCHING`.
