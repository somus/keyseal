# Integrating KeySeal

This guide adds token signing to a web application. The pieces are the signing service on your private network, `@keyseal/server` in your backend, `@keyseal/browser` in your page, and the KeySeal helper on each signer's computer. [examples/reference-server](../examples/reference-server/) wires all of them together and is the quickest way to see a job end to end.

```
 browser page ──(your API)──> your backend ──> signing service
      │                          ▲  @keyseal/server       (private network)
      │ keyseal:// link            │
      ▼                          │ job endpoint, HTTPS
 keyseal helper ───────────────────┘
      │
 USB token (PKCS#11, Windows CNG or macOS CryptoTokenKit)
```

## 1. Run the signing service

Run the service image where only your backend can reach it, with a strong bearer token:

```sh
docker run -p 127.0.0.1:8090:8080 \
  -e SIGNING_SERVICE_TOKEN="$(openssl rand -base64 32)" \
  ghcr.io/somus/keyseal-service:0.3
```

It trusts the CCA India roots by default; for another PKI, set `SIGNING_TRUST_ROOTS_DIR` to a directory of its roots and intermediates, or `SIGNING_EXTRA_TRUST_ROOTS_DIR` to trust it alongside them. [service/README.md](../service/README.md) covers its routes, environment, timestamp authority and plugins (extra stamp styles and routes in a derived image).

## 2. Serve the job endpoint

Install `@keyseal/server` and create one instance for your app:

```ts
import { createKeySeal, ServiceClient } from "@keyseal/server";

export const keyseal = createKeySeal({
  adapter, // your job store, blob store and completion callback
  service: new ServiceClient({ url: SIGNING_SERVICE_URL, token: SIGNING_SERVICE_TOKEN }),
  origin: "https://app.example.org",
  basePath: "/api/keyseal",
  branding: {
    name: "Example Trust",
    icon: "https://app.example.org/keyseal-logo.png",
    accentColor: "#1f6feb",
  },
  minHelperVersion: "0.3.0",
});
```

Route requests to `keyseal.handle(request)`; it answers the manifest at `/.well-known/keyseal.json` and the job endpoint under `basePath`, and returns 404 for anything else. The helper calls these routes directly, without your session, so they authenticate by the job token alone.

The adapter stores jobs and blobs (Postgres and S3, for example) and receives the result in `onCompleted`. Its contract, including the atomic `transition` the settle lease relies on, is in [packages/server/README.md](../packages/server/README.md). `createMemoryAdapter` is enough for tests.

Creating a job expires old jobs and deletes their PDFs and signing states. Run `await keyseal.sweep()` from a scheduler, such as a cron job every five minutes, so that also happens when no one is creating jobs, and to clear blobs a failed deletion left behind.

`service` can be any object with `ServiceClient`'s `certificate`, `signStart` and `signFinish` methods, for a proxy, retries or tests; see the server README for the errors it throws.

### Branding

`branding` is served as the manifest the helper reads for each job. In the job window:

- `name` appears in small text above your site's name.
- `icon`, a square PNG on the same origin of at most 256 KiB (128 by 128 pixels or larger looks sharp), fills the header tile, with a small badge saying whether the job signs or enrols.
- `accentColor` colours the window's top edge, the primary button, the focus ring and the selection. The button text is white or black, whichever contrasts better.
- `translucent: false` makes the job window opaque on macOS, where it is otherwise glass. Signers can also turn glass off in the helper's Settings, and macOS's Reduce transparency turns it off for every window.

Branding never appears on the first-contact prompt, and the site's name always stays the heading, so a manifest can't dress up an unknown origin.

## 3. Create jobs

Create jobs from your own authenticated API, for the signed-in user:

```ts
const pdf = await service.prepare(original, [
  { name: "Signature1", page: -1, box: [360, 40, 560, 110] },
]);
const { id, link } = await keyseal.createSignJob({
  title: "Board resolution 2026/14",
  signer: "Asha Rao",
  documents: [
    {
      pdf,
      fieldName: "Signature1",
      signatureDetails: { reason: "Approved as Director", location: "Mumbai" },
    },
  ],
  expectedCertificateSha256, // the signer's enrolled certificate
  reference: "resolution-14",
});
```

Return `link` to the page and keep `id` for status checks with `keyseal.status(id)`. The job token in `link` is the helper's credential for the job endpoint; your server never needs it again, so don't store or log it. `expectedCertificateSha256` is strongly recommended: without it, any valid certificate on any token can sign. Each document's `signatureDetails` is optional: its `reason`, `location` and `contactInfo` (up to 200 characters each) appear in the signature panel of PDF viewers, and the built-in stamp shows the reason. An enrol job (`createEnrolJob`) captures the signer's certificate first, so you can pin it on later sign jobs.

### Several documents at once

`documents` takes up to 20 PDFs, which the signer signs together with one PIN entry. Give the job a `title` that describes the batch and each document its own `title`:

```ts
await keyseal.createSignJob({
  title: "Board pack, March 2026",
  signer: "Asha Rao",
  documents: [
    { pdf: resolution, fieldName: "Signature1", title: "Resolution 2026/14" },
    { pdf: minutes, fieldName: "Signature1", title: "Minutes of 12 March 2026" },
  ],
  expectedCertificateSha256,
});
```

The helper shows how many documents there are, with each title and its fingerprint under "Show technical details". Each PDF may be up to 25 MiB, and together at most 240 MiB. The job completes only if every document is signed: `onCompleted` receives `result.pdfs` in the order of `documents`, all at once, and a document that fails any check fails the whole job. A single document is a list of one, and its `title` defaults to the job's.

Where you can't pin a certificate yet, on enrolment or a signer's first job, `certificatePolicy` narrows which certificates the job accepts:

```ts
await keyseal.createEnrolJob({
  title: "DSC enrolment",
  signer: "Asha Rao",
  certificatePolicy: {
    policyOids: ["2.16.356.100.2.3"], // at least one of these in certificatePolicies
    issuerCommonNames: ["Example Sub CA for Class 3 Individual"], // the issuing CA's CN, exactly
    subjectOrganization: "Example Trust", // the subject's O, exactly
  },
});
```

Every member you give must hold, and a policy may hold only `keyUsage`. The helper offers only certificates that satisfy the policy and tells the signer when none on their token does; the server refuses anything else with 422 and fails the job. The policy narrows the job to a class, an issuer or an organization, not to a person, so check the enrolled certificate against the signer in `onCompleted` and pin it afterwards.

Indian DSCs mark their class with CCA India certificate policy OIDs: `2.16.356.100.2.2` for Class 2 and `2.16.356.100.2.3` for Class 3, from the CCA's [OID Hierarchy for India PKI](https://cca.gov.in/sites/files/pdf/guidelines/CCA-OID.pdf). Under the CCA's [interoperability guidelines](https://cca.gov.in/sites/files/pdf/guidelines/CCA-IOG.pdf) a certificate carries the OID of its class and of every lower class, so `["2.16.356.100.2.3"]` admits Class 3 only. This is an example; check the OIDs and CA names your signers' certificates carry before relying on them.

Every job also requires a key usage. By default the certificate's KeyUsage extension must assert nonRepudiation, as Indian DSCs and qualified signing certificates do. Some tokens sign with a certificate that asserts digitalSignature only, such as the PIV Authentication certificate on a corporate PIV card; set `keyUsage: "digitalSignature"` to accept those as well as nonRepudiation ones:

```ts
await keyseal.createSignJob({
  title: "Purchase order 4471",
  signer: "Asha Rao",
  documents: [{ pdf, fieldName: "Signature1" }],
  certificatePolicy: {
    keyUsage: "digitalSignature", // digitalSignature or nonRepudiation; the default is "nonRepudiation"
    issuerCommonNames: ["Example Corp PIV Issuing CA"],
  },
});
```

A certificate without a KeyUsage extension, or a CA certificate, never qualifies. The server passes the job's key usage to the signing service's certificate check in both rounds; when you validate a signed PDF yourself, pass the same value as `service.validate(pdf, base, keyUsage)`.

In `onCompleted`, check the result against your own rules (for example, that the certificate is in the signer's name) and throw `JobRefused` to fail the job with a message the user sees.

## 4. Start the helper from the page

```ts
import { helperDownloadFor, signWithHelper } from "@keyseal/browser";

const status = await signWithHelper({
  link,
  getStatus: () => fetch(`/api/sign-jobs/${jobId}`).then((r) => r.json()),
  onChange: (status) => showStatus(status), // hide the download link once it isn't pending
  onNotClaimed: async () => showDidntOpen(await helperDownloadFor(navigator)),
});
```

Call it straight from the click handler, since browsers want a recent user gesture before opening an app. The link opens in a hidden iframe, so if your site sends a Content-Security-Policy, add `keyseal:` to `frame-src`. Otherwise browsers block the link silently and the helper never opens. `onNotClaimed` fires when the helper hasn't picked up the job within about five seconds. That doesn't mean it isn't installed: the browser may ask whether to open KeySeal, and the first time a signer meets your site the helper asks them to trust its origin before it fetches the job (spec section 5). So show a "Didn't open? Download the helper" link beside the job's status, never a screen that only offers the install, and hide the link once the status moves past `pending`. The job stays open, so a fresh install can still pick it up. [packages/browser/README.md](../packages/browser/README.md) has the full options and a React example.

## 5. Install the helper

Signers install the helper once. Each release carries its downloads under fixed names too, so link to the latest release's and never update the links:

| Platform | Download link | Registers `keyseal://` |
| --- | --- | --- |
| macOS | `https://github.com/somus/keyseal/releases/latest/download/keyseal-macos-universal.dmg`, the universal app | When the app is first opened |
| Windows | `https://github.com/somus/keyseal/releases/latest/download/keyseal-windows-x64.zip`, with `keyseal.exe` and `install.cmd` | `install.cmd` |
| Linux | `https://github.com/somus/keyseal/releases/latest/download/keyseal-linux-x64.AppImage` or `keyseal_amd64.deb`, and on arm64 `keyseal-linux-arm64.AppImage` or `keyseal_arm64.deb`; the tarballs are on the release page | The deb on install; `keyseal install` for the AppImage and tarball |

`await helperDownloadFor(navigator)` from `@keyseal/browser` says which one suits the signer's platform: `macos`, `windows`, `linux-x64`, `linux-arm64` or `unsupported`. On Linux it asks Chromium's client hints for the architecture, since Chromium's user agent says x86_64 on every machine, and reads the user agent in other browsers.

The helper updates itself. Raising `minHelperVersion` makes older helpers update before they can sign, so raise it only once that release exists.

If a signer's token isn't found, opening KeySeal on its own shows Settings, where Tokens and drivers lists what it found and Copy diagnostics gives support the full report. `keyseal doctor` prints the same report in a terminal.

## Before going live

- Serve the job endpoint over HTTPS on a domain name. `allowInsecureOrigin` and the helper's `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` are for development only.
- If you send a Content-Security-Policy, allow `keyseal:` in `frame-src`. Development servers often send no CSP, so this only shows up in production.
- Try a first contact with the helper installed: leave its trust prompt open past five seconds and check that the page keeps the job's status on screen next to the download link.
- Keep the signing service off the public internet.
- Pin `expectedCertificateSha256` on sign jobs, and set `certificatePolicy` where you can't pin yet.
- Pass `rateLimit` to `createKeySeal` if the job endpoint isn't rate limited at your edge.
- Make `onCompleted` idempotent on `job.id`: a retry after a lapsed settle lease may call it again.
