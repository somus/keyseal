# KeySeal protocol v1

Status: draft. This document is normative except where a section or paragraph is marked informative. The machine-readable companion is [openapi.yaml](openapi.yaml); the schema names used here (`Manifest`, `JobDescription`, `DocumentEntry`, `CertificateSubmission`, `PreparedSignature`, `EnrolResult`, `SignatureSubmission`, `FailureReport`, `Empty`, `Error`, `UpgradeRequired`) are the names of its component schemas. Where the two disagree, this document wins and the disagreement is a bug.

## 1. Conventions and terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

A length given in characters counts Unicode code points, so U+1F600 is one character even though UTF-16 needs two code units for it. A length given in bytes counts octets.

- **Job**: one signing or enrolment request created by the integrator backend for one person. A job has a kind, `sign` or `enrol`.
- **Document**: one PDF of a sign job. A sign job carries 1 to 20 documents, signed with one certificate after one PIN entry; it completes only when every document is signed, and otherwise fails as a whole.
- **Job token**: the opaque secret that identifies a job. It is the last path segment of the job URL.
- **Job URL**: the absolute HTTPS URL of a job on the integrator backend (section 3.2).
- **Origin**: the scheme, host and port of the job URL, as defined in RFC 6454.
- **Claim**: the first `GET` of the job URL, which binds the job to one helper run.
- **Claim nonce**: the secret the server returns with the claim. Every later request for the job carries it.
- **Manifest**: the JSON document at `/.well-known/keyseal.json` on the origin (section 6).
- **Settle lease**: the server-side lock a state-changing request holds on a job while it runs (section 9.3).
- **SignedAttributes**: the DER encoding of the CMS `SignedAttributes` of the signature being created, with the outer tag SET OF (0x31), exactly the bytes the signature is computed over.

## 2. Scope and roles

This specification defines the `keyseal://` link, the origin and trust rules, the manifest, the job endpoint the helper talks to, the checks the helper performs before signing, and what the helper shows the user. It does not define how the integrator backend creates jobs, how the browser page learns a job's progress, or the interface between the integrator backend and the signing service.

There are four roles.

- **Browser page**: the integrator's web page. It obtains a job URL from its own backend, opens the `keyseal://` link and follows the job's progress through its own backend. It takes no part in the exchanges defined here beyond opening the link. `@keyseal/browser` implements this role.
- **Integrator backend**: the integrator's server. It creates jobs, serves the manifest and the job endpoint, and is the only party that talks to the signing service. `@keyseal/server` implements the job endpoint as Fetch-API handlers; the integrator supplies job storage, state blobs and a completion callback.
- **Helper**: the desktop application registered for the `keyseal://` scheme. It reads certificates from the user's token, checks what it is asked to sign, asks for the PIN and signs. It talks only to the job origin.
- **Signing service**: the pyHanko service that prepares and finishes PDF signatures. Only the integrator backend reaches it. The helper MUST NOT contact the signing service, and nothing the server sends to the helper MUST name the service's address or credentials.

Informative: the browser page detects that the helper started by watching for the job to reach the `claimed` state through the integrator's own status endpoint. `@keyseal/browser` polls by default and can use SSE. If no claim arrives within about 5 seconds, the page shows the download link while the job stays open, so a fresh install can still claim it.

## 3. The `keyseal://` link

### 3.1 Syntax

A link has one of two forms:

```
keyseal://sign?job=<job URL>
keyseal://enrol?job=<job URL>
```

`<job URL>` is percent-encoded as a query component value. Examples:

```
keyseal://sign?job=https%3A%2F%2Fdash.example.org%2Fapi%2Fkeyseal%2Fv1%2Fjobs%2Fq3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk
keyseal://enrol?job=https%3A%2F%2Fdash.example.org%2Fv1%2Fjobs%2FAbCdEfGhIjKlMnOpQrSt
```

The link carries no protocol version of its own. It is versioned through the job URL it points at (section 7).

### 3.2 Job URL

A job URL MUST:

1. Be an absolute URL whose scheme is `https`, except as allowed by section 4.4.
2. Have no userinfo, no query and no fragment.
3. Have a host that satisfies section 4.
4. Have a path of the form `<base>/v1/jobs/<token>`, where `<base>` is empty or any path the integrator chooses, starting with `/` and not ending with `/`.
5. End in a token matching `^[A-Za-z0-9_-]{20,128}$`.

The endpoints of a job are the job URL itself and the job URL followed by `/certificate`, `/signature`, `/failure` or `/documents/<index>`, where `<index>` is a document's 0-based position in the job, in decimal without leading zeros (section 8.4). A request with a method other than the one its endpoint defines gets `404`.

### 3.3 Validation by the helper

Before making any network request, the helper MUST check that:

1. The link is at most 2048 bytes long.
2. The scheme is `keyseal`.
3. The host (the action) is exactly `sign` or `enrol`, and the path is empty or `/`.
4. The query contains exactly one `job` parameter. Other parameters MUST be ignored.
5. The percent-decoded `job` value is a job URL as defined in section 3.2.

If any check fails, the helper MUST show an error and MUST NOT make any network request.

## 4. Origin rules

### 4.1 Origin

The origin of a job is the origin of its job URL. The host is compared in lowercase ASCII; an internationalised host is compared in its A-label (punycode) form. The manifest, the icon, the document URLs and every job endpoint request MUST be on the job origin. The helper MUST NOT make a request for a job to any other origin.

### 4.2 Allowed hosts

The helper MUST refuse a job URL whose host:

- is an IPv4 or IPv6 literal;
- is `localhost` or ends in `.localhost`;
- resolves to an address in a loopback, unspecified, private or link-local range: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`, and IPv4-mapped IPv6 forms of the IPv4 ranges.

The resolution check applies to the address of every connection the helper opens for the job, not only to the first lookup, so that a DNS answer that changes during the job cannot reach a private address.

The helper MUST validate the server's TLS certificate against the system trust store and MUST NOT offer a way to skip validation.

### 4.3 Redirects

The helper MUST NOT follow a redirect whose target has a different origin from the job origin; such a response is a failure of the request. The helper MAY follow same-origin redirects, at most 5 per request. Servers SHOULD NOT redirect job endpoint requests.

### 4.4 Development override

When the helper's environment contains `KEYSEAL_ALLOW_INSECURE_ORIGINS=1`, the helper MUST also accept job URLs whose origin is `http://localhost` or `http://127.0.0.1`, on any port. For such origins:

- section 4.2 does not apply to that host;
- the helper MUST show an insecure-origin banner in every window for the job;
- the helper MUST NOT write the origin to the trust store, so every job from it is a first contact (section 5).

No other value of the variable, and no other setting, relaxes the origin rules. `https://localhost`, other hosts on `http`, and other loopback addresses remain refused.

## 5. Trust on first use

The helper keeps a trust store of origins. A record holds exactly the origin and the time it was trusted.

1. After validating the link (section 3.3) and before any network request to the origin, the helper MUST look the origin up in the trust store. Matching is exact on scheme, host and port.
2. If the origin is not in the store, this is a first contact, for either job kind. The helper MUST show a first-contact prompt that names the origin and asks whether to trust it. The prompt MUST NOT show anything taken from the manifest or the job: no name, icon, accent colour, title or signer.
3. If the user declines, the helper MUST stop without making any request to the origin. The job stays `pending` and expires.
4. If the user accepts, the helper MUST store the origin and the current time, then continue.
5. Branding changes never cause a new prompt.

The user MUST be able to revoke trust in an origin, which deletes its record. The helper provides this as `doctor --forget <origin>` and as a list in its settings window.

## 6. Manifest

### 6.1 Location and fetch

The manifest is served at `GET <origin>/.well-known/keyseal.json` with `Content-Type: application/json`. It is OPTIONAL; without it the helper shows no branding.

For every job, after section 5 and before claiming the job, the helper SHOULD fetch the manifest and, if it names one, the icon. Both fetches together MUST finish within 2 seconds; the helper MUST NOT wait longer. The helper MUST ignore a manifest larger than 16384 bytes.

If the fetch succeeds and the manifest is valid, the helper MUST use it and replace its cached copy for that origin. Otherwise (timeout, network error, any non-200 status, invalid JSON or schema violation) the helper MUST use its cached copy for the origin if it has one, and no branding if it does not. A manifest never affects trust (section 5) and its absence never stops a job.

### 6.2 Members

The manifest is a JSON object (`Manifest`):

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `protocol` | integer | yes | Protocol version. MUST be `1`. |
| `name` | string, 1 to 64 characters | yes | Display name of the integrator. |
| `icon` | string | no | Absolute URL of a PNG on the job origin, at most 262144 bytes. |
| `accentColor` | string `#rrggbb` | no | One accent colour; hex digits in either case. |
| `translucent` | boolean | no | `false` asks for opaque job windows. Absent means `true`. |
| `minHelperVersion` | string, SemVer 2.0.0 | no | Lowest helper version this origin serves. |

The helper MUST treat a manifest whose `protocol` is not `1` as invalid.

The helper MUST ignore an `icon` that is not on the job origin, is larger than 262144 bytes, or does not start with the PNG signature. Ignoring the icon does not invalidate the rest of the manifest.

Where the helper makes its windows translucent, it SHOULD make an origin's job windows opaque when the manifest's `translucent` is `false`. The member never makes a window translucent that the helper or the user would show opaque, and it does not apply to the first-contact prompt.

If the helper's version is lower than `minHelperVersion` by SemVer precedence, the helper SHOULD NOT claim the job and SHOULD tell the user to update. The server's `426` refusal (section 7.3) is the authoritative check.

### 6.3 Prohibited content

A manifest MUST NOT name PKCS#11 module paths, driver names, or any other hint for module selection. Module selection is the helper's decision alone. The helper MUST ignore unknown members, so such content has no effect. The same rule applies to every job endpoint response.

### 6.4 Where branding appears

Branding (name, icon, accent colour) MAY appear in the helper's windows for a job on a trusted origin. It MUST NOT appear on the first-contact prompt, and it MUST NOT replace, hide or visually outweigh the origin wherever the origin is shown.

## 7. Versioning

### 7.1 Protocol version

This document defines protocol version 1. It appears as `"protocol": 1` in the manifest and as the `v1` path segment of the job URL. A helper that does not support the version in a job URL MUST refuse the link.

Within version 1, new OPTIONAL members MAY be added to requests and responses. Receivers MUST ignore members they do not know. A change that alters or removes the meaning of an existing member, or adds a required one, needs a new protocol version and a new path segment.

### 7.2 `X-KeySeal-Version`

The helper MUST send `X-KeySeal-Version: <version>` on every request it makes to the origin, where `<version>` is the helper's own version as a SemVer 2.0.0 string, for example `X-KeySeal-Version: 1.2.0`. The helper version is independent of the protocol version.

### 7.3 Minimum helper version

A server MAY be configured with a minimum helper version. If it is, the server MUST compare `X-KeySeal-Version` to it by SemVer precedence on every job endpoint request, and MUST treat a missing or unparseable header as lower. A lower version gets `426 Upgrade Required` with an `UpgradeRequired` body:

```json
{ "minVersion": "1.2.0", "message": "Update the signing helper, then try again." }
```

The server SHOULD also mark the job `failed` with the same message, so the browser page can show the reason, when the job is `pending`, or when the request is a `POST` whose body carries the job's claim nonce and no other request holds a live settle lease (section 9.3). In every other case the `426` leaves the job unchanged, so a request that has only the token, such as one replayed from a leaked link, cannot end a claimed job.

On `426` the helper MUST stop the job, MUST show the message and `minVersion`, and SHOULD run an update check (section 13) even if one ran within the last day.

## 8. Job endpoint

### 8.1 Common rules

- Every request MUST carry `X-KeySeal-Version` (section 7.2).
- Request bodies MUST be JSON objects encoded as UTF-8 with `Content-Type: application/json`. A server MUST refuse a body larger than 262144 bytes with `413`. A server need not check the request `Content-Type`; it parses the body as JSON whatever the header says.
- Every response body MUST be a JSON object with `Content-Type: application/json`, and every response MUST carry `Cache-Control: no-store`.
- Binary values are base64 as defined in RFC 4648 section 4, with padding. Certificates are base64 of their DER encoding.
- SHA-256 values are 64 lowercase hex characters.
- Every `POST` body carries the `claimNonce` from the claim. The server MUST store the claim nonce only as its SHA-256, as it does the token (section 9.4), and MUST compare it in constant time.

The server evaluates a request in this order and answers with the first status that applies:

1. Rate limit exceeded: `429`.
2. Token does not match `^[A-Za-z0-9_-]{20,128}$`: `404`.
3. Helper version below the configured minimum: `426` (section 7.3).
4. No job for the token, or the job is `expired`: `404`.
5. Job is `completed` or `failed`: `410`.
6. Body larger than 262144 bytes: `413`. Body not valid JSON or not matching its schema: `422`; the job's state does not change.
7. `claimNonce` does not match, the job is not in the state the request needs, or another request holds a live settle lease: `409`.
8. The request is processed.

A `426` changes the job only as section 7.3 allows. To find the claim nonce the server reads the body; a body it cannot read or parse leaves the job unchanged.

### 8.2 Claim: `GET <job URL>`

If the job is `pending`, the server MUST atomically move it to `claimed`, generate a claim nonce, and return `200` with a `JobDescription`:

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `kind` | `"sign"` or `"enrol"` | yes | Job kind. |
| `title` | string, 1 to 200 characters | yes | What is being signed or enrolled, for display. For a sign job with several documents it describes them together, such as "Board pack, 12 documents". |
| `signer` | string, 1 to 200 characters | yes | Name of the person expected to sign, for display. |
| `claimNonce` | string matching `^[A-Za-z0-9_-]{20,128}$` | yes | Secret for every later request. |
| `expectedCertificateSha256` | 64 lowercase hex | no | SHA-256 of the DER certificate the helper must use. |
| `certificatePolicy` | `CertificatePolicy` | no | What the certificate must show, for jobs that cannot name one certificate in advance. |
| `digestAlgorithm` | `"sha256"` or `"sha384"` | no, `sign` only | Digest the server will ask for in round 1. Present only when the integrator fixed the digest when creating the job. |
| `documents` | array of 1 to 20 `DocumentEntry` | yes for `sign`, absent for `enrol` | The documents to sign, in order. |

A `DocumentEntry` is an object:

| Member | Type | Required | Meaning |
| --- | --- | --- | --- |
| `title` | string, 1 to 200 characters | yes | The document's own title, for display. |
| `document` | absolute URL on the job origin | yes | Where the helper can download the prepared PDF (section 8.4): the job URL followed by `/documents/<index>`, where `<index>` is the entry's 0-based position in `documents`. |

The documents of a job are signed with one certificate, one digest and one signature scheme, after one PIN entry. Every request after the claim covers all of them at once: round 1 prepares every document, and round 2 carries every signature.

A `CertificatePolicy` is an object with at least one of these members:

| Member | Type | The certificate satisfies it when |
| --- | --- | --- |
| `policyOids` | array of 1 to 16 OIDs, each in dotted-decimal form matching `^[0-2](\.(0\|[1-9][0-9]*))+$` and at most 128 characters | Its certificatePolicies extension (RFC 5280 section 4.2.1.4) holds at least one of them as a `policyIdentifier`. |
| `issuerCommonNames` | array of 1 to 16 strings, each 1 to 200 characters | The common name (CN) of its issuer name, which is the subject CN of the CA that issued it, equals one of them. |
| `subjectOrganization` | string, 1 to 200 characters | The organization (O) of its subject name equals it. |

A certificate satisfies the policy when it satisfies every member present. Strings compare exactly, code point by code point, without case folding or normalisation. A name with no CN or O attribute, or with more than one, satisfies no member that reads it. Policy qualifiers are ignored, and `anyPolicy` in a certificate matches only an OID list that names it. A server MUST NOT send `certificatePolicy` without a member.

Informative: Indian DSCs mark their class with CCA India certificate policy OIDs, `2.16.356.100.2.2` for Class 2 and `2.16.356.100.2.3` for Class 3 (CCA, *OID Hierarchy for India PKI*). The CCA interoperability guidelines have a certificate carry the OID of its class and of every lower class, so `policyOids: ["2.16.356.100.2.3"]` admits Class 3 certificates only and `["2.16.356.100.2.2"]` admits Class 2 and Class 3.

The claim nonce MUST come from a CSPRNG with at least 128 bits of entropy; 32 random bytes encoded as unpadded base64url is RECOMMENDED. The server MUST NOT return it again. If the job is already `claimed` or `prepared`, the server MUST answer `409` and MUST NOT change the job.

The helper MUST then:

1. Check that `kind` equals the link's action, and for a sign job that `documents` has 1 to 20 entries whose `document` is the job URL followed by `/documents/<index>` for the entry's own index. If not, report a failure (section 8.7) and stop.
2. Find the certificates on the token whose key is supported (section 11); section 12.1 says when the helper may log in first. If `expectedCertificateSha256` is present, keep only the certificate whose DER SHA-256 equals it. If `certificatePolicy` is present, keep only the certificates that satisfy it. If none remain, report a failure and stop, with a message that says plainly that the token holds no certificate the origin accepts for the job. If more than one remains, the user chooses.
3. Continue with section 8.3 for `sign` or section 8.6 for `enrol`.

### 8.3 Sign round 1: `POST <job URL>/certificate`

Request, `CertificateSubmission`:

```json
{ "claimNonce": "...", "certificate": "<base64 DER>", "chain": ["<base64 DER>"] }
```

`certificate` is the chosen certificate, at most 16384 characters. `chain` holds the other certificates found on the token, at most 8 entries of at most 16384 characters each, in any order; it MAY be empty.

The job MUST be `claimed`. The server MUST refuse the certificate with `422` unless it parses as an X.509 certificate, is valid at the time of the request, has a key supported by section 11, chains to a root the signing service trusts, if the job has an expected certificate has that SHA-256, if the job has a certificate policy satisfies it (section 8.2), and, if the job description carried `digestAlgorithm`, has a key whose digest under section 11 is that value. A refused certificate fails the job (section 8.8). For `issuerCommonNames` the server MAY read the CN from the certificate's issuer name rather than from the CA certificate on the path: a path to a trusted root links each certificate to its issuer by name and by signature (RFC 5280 section 6), so a certificate that passes the chain check names the CA that issued it. Otherwise the server asks the signing service to prepare a signature in every document with the certificate and chain, stores what it needs to finish each of them, moves the job to `prepared` and returns `200` with a `PreparedSignature`:

| Member | Type | Meaning |
| --- | --- | --- |
| `digestAlgorithm` | `"sha256"` or `"sha384"` | Digest for every signature, chosen by section 11. |
| `signatureAlgorithm` | `"rsa-pkcs1-v1_5"`, `"rsa-pss"` or `"ecdsa"` | Signature scheme the server will embed in every document. |
| `documents` | array of `{ "toSign": <base64> }` | One entry per document, in the order and number of the job description's `documents`. `toSign` is that document's SignedAttributes, DER, outer tag 0x31. |

If the job description carried `digestAlgorithm`, the server MUST return the same value. If preparing any document fails, the server prepares none: the job stays `claimed` on a `502`, or fails on a refusal (section 8.8).

The helper MUST then check that `documents` has as many entries as the job description's, MUST validate every `toSign` (section 10) with the SHA-256 of the certificate it posted, and MUST check that `digestAlgorithm` equals the one in the job description if that was present and that `digestAlgorithm` and `signatureAlgorithm` suit the key (section 11). Any failure, for any document: report a failure and stop without signing any document, before the PIN prompt or, when the helper logged in first (section 12.1), before the confirmation prompt.

### 8.4 Document download

After round 1 and before showing the digests (section 12.1), the helper fetches every document of the job description's `documents`, and checks each against the `toSign` at the same index:

- Request: `GET <document>` with `Authorization: Bearer <job token>`, `X-KeySeal-Claim: <claim nonce>` and `X-KeySeal-Version`.
- The server evaluates the request in the order of section 8.1: `429`, `404` for a malformed token, `426`, `404` for an unknown or expired job, `410` for a terminal one. It MUST then check that the bearer token equals the token in the document URL's path and compare `X-KeySeal-Claim` with the job's claim nonce in constant time, answering `403` if either header is missing or does not match. A `pending` job has no claim nonce yet and gets `403`. It MUST answer `409` while the job is `claimed`, `404` for an index the job has no document at, and serve the document only while the job is `prepared`.
- Response: `200` with `Content-Type: application/pdf`; the body is the prepared PDF that contains the signature placeholder its `toSign` was computed for.

The helper MUST refuse a document larger than 67108864 bytes (64 MiB), and a job whose documents together are larger than 268435456 bytes (256 MiB). A server MUST NOT serve a job whose prepared documents together exceed that.

For each document, the helper MUST take the last `/ByteRange` in the file as the signature being created, and MUST check that it has the form `[0 a b c]`, that the gap from offset `a` to `b` is exactly the `/Contents` hex string of that signature including its delimiters, and that `b + c` equals the file length. It MUST then hash bytes `[0, a)` and `[b, b + c)` with `digestAlgorithm` and compare the result with the `messageDigest` attribute of that document's `toSign`. Any mismatch or a failed download, for any document: report a failure and stop without signing any document.

### 8.5 Sign round 2: `POST <job URL>/signature`

Request, `SignatureSubmission`:

```json
{ "claimNonce": "...", "signatures": ["<base64>", "<base64>"] }
```

`signatures` holds one signature per document, in the order of the job description's `documents`, each at most 4096 characters and encoded as section 11 describes. A list of another length does not match the schema: `422`, and the job is unchanged. The job MUST be `prepared`.

The server MUST verify every signature over its document's `toSign` with the round 1 certificate before it finishes any document, and MUST refuse the request with `422`, failing the job, when any of them does not verify. Otherwise it asks the signing service to finish every PDF. Only when every document is finished does it hand the signed PDFs to the integrator, all at once and in order, move the job to `completed`, and return `200` with `Empty` (`{}`). When finishing any document fails, the integrator receives none of them: a refusal fails the job, and any other failure is a `502` that leaves the job `prepared` (section 8.8).

### 8.6 Enrol: `POST <job URL>/certificate`

Enrol is a single round. The request is a `CertificateSubmission` as in section 8.3. The job MUST be `claimed`. The server MUST apply the certificate checks of section 8.3: it refuses with `422`, failing the job, a certificate that does not parse as X.509, is not valid at the time of the request, has a key not supported by section 11, does not match the expected SHA-256, does not satisfy the job's certificate policy, or does not chain to a root the signing service trusts. It MAY refuse other certificates by its own policy. On acceptance it moves the job to `completed`, hands the certificate and chain to the integrator, and returns `200` with `EnrolResult` (`{}`). What the integrator stores is its own policy.

The helper MAY log in to the token to read certificates for an enrol job, after showing what section 12.2 requires.

### 8.7 Failure: `POST <job URL>/failure`

Request, `FailureReport`:

```json
{ "claimNonce": "...", "message": "Signing cancelled." }
```

`message` is 1 to 500 characters after trimming whitespace, written for the user. The job MUST be `claimed` or `prepared`. The server moves the job to `failed`, keeps the message for the browser page, and returns `200` with `Empty`.

After a successful claim, the helper MUST send a failure report whenever it stops the job without completing it: the user cancels, no usable certificate or token is found, a validation in sections 8.2 to 8.4 or 10 fails, the PIN is wrong or the token is locked, or signing fails. Sending is best effort; the helper shows the reason in its own window regardless. The message MUST NOT contain the PIN or any secret.

### 8.8 Status codes

| Status | Meaning | Body |
| --- | --- | --- |
| `200` | Success. | Per endpoint. |
| `403` | Document download (section 8.4) without the matching bearer token or claim nonce. | `Error` |
| `404` | Token malformed or unknown, job expired, or wrong method for the endpoint. | `Error` |
| `409` | Job already claimed (on `GET`), `claimNonce` does not match, job in the wrong state for the request, or another request holds the settle lease. | `Error` |
| `410` | Job is `completed` or `failed`. | `Error` |
| `413` | Body larger than 262144 bytes. | `Error` |
| `422` | Body not valid JSON or not matching its schema, or the server refused the certificate or a signature. | `Error` |
| `426` | Helper version below the server's minimum. | `UpgradeRequired` |
| `429` | Rate limit exceeded. The server MAY send `Retry-After`. | `Error` |
| `502` | The signing service is unreachable or answered with an error other than `400` or `422`. | `Error` |

A `422` for an invalid body leaves the job unchanged. A `422` that refuses a certificate or a signature moves the job to `failed` with the same message; for a sign job with several documents, one refused document fails the whole job. When the signing service answers a request with `400` or `422`, the server treats it as a refusal: `422`, and the job fails with the service's message. Any other error status from the service, a network error or a timeout is a `502`.

On `502` the server releases its settle lease and leaves the job unchanged. The helper MAY repeat the same request once after a short delay.

### 8.9 Error bodies

Every non-`200` response except `426` carries an `Error` body, `{ "message": "..." }`, with a message written for the user. The helper MUST show it as plain text, attributed to the origin. The status code is the machine-readable result; there is no separate error code.

## 9. Job lifecycle

### 9.1 States

| State | Meaning |
| --- | --- |
| `pending` | Created, not yet claimed. |
| `claimed` | A helper claimed it with `GET`; a claim nonce exists. |
| `prepared` | Sign round 1 succeeded; the server holds the SignedAttributes and finishing state of every document. |
| `completed` | Every signed PDF finished, or certificate enrolled. Terminal. |
| `failed` | Helper reported failure, the server refused a certificate or signature, or the helper was refused as outdated. Terminal. |
| `expired` | TTL passed in a non-terminal state. Terminal. |

### 9.2 Transitions

| From | To | Trigger |
| --- | --- | --- |
| `pending` | `claimed` | `GET <job URL>` |
| `pending`, `claimed`, `prepared` | `failed` | `426` refusal, under the conditions of section 7.3 (SHOULD) |
| `claimed` | `prepared` | Sign round 1 accepted |
| `claimed` | `completed` | Enrol certificate accepted |
| `prepared` | `completed` | Sign round 2 accepted |
| `claimed`, `prepared` | `failed` | Failure report, or certificate or signature refused |
| `pending`, `claimed`, `prepared` | `expired` | 15 minutes since creation |

A job expires 15 minutes after it is created, whatever its state. The server MUST evaluate expiry on every read of the job and answer as for an expired job from that moment on; it MAY record `expired` lazily and MAY sweep expired jobs in the background. A request that acquired the settle lease before expiry MAY finish its transition, so a sweep MUST NOT record `expired` on a job whose settle lease is live.

### 9.3 Settle lease

`POST` requests to `/certificate`, `/signature` and `/failure` change state and run under a settle lease:

1. After the checks in section 8.1, the server MUST acquire the lease atomically. Acquisition succeeds only if the job is in a state the request needs and no lease is held or the held lease started more than 5 minutes ago. Otherwise the server answers `409`.
2. The request may move the job to its next state only while it still holds its lease, checked atomically with the state change. A request whose lease was taken over MUST NOT change the job and answers as for the job's current state.
3. A request that ends without changing the job's state MUST release its lease.

The lease bounds how long one server process may hold a job; after 5 minutes a repeated request may take it over. It does not limit how long the helper may take between requests, which only the TTL does. The helper MAY repeat a `POST` with the same body after a network failure.

### 9.4 Token

- The server MUST generate the token from a CSPRNG with at least 128 bits of entropy. 32 random bytes encoded as unpadded base64url (43 characters) is RECOMMENDED.
- The server MUST store only the SHA-256 of the token and look jobs up by that hash. It MUST NOT log the token.
- The token is single use: it can claim the job once. After the claim, no request for the job succeeds without the claim nonce. The document downloads (section 8.4) carry it in `X-KeySeal-Claim` and also need the job in the `prepared` state.

## 10. SignedAttributes validation

Before showing the digests to the user (section 12.1), the helper MUST parse every document's `toSign` as DER SignedAttributes and MUST refuse to sign any document unless all of the following hold for each:

1. The outer tag is SET (0x31) containing a sequence of `Attribute` (SEQUENCE { OID, SET OF value }).
2. `contentType` (1.2.840.113549.1.9.3) is present exactly once with value OID id-data (1.2.840.113549.1.7.1).
3. `messageDigest` (1.2.840.113549.1.9.4) is present exactly once, an OCTET STRING of length 32 for `sha256` or 48 for `sha384`, matching the round 1 `digestAlgorithm`.
4. `signing-certificate-v2` (1.2.840.113549.1.9.16.2.47) is present exactly once, and the first `ESSCertIDv2` `certHash` equals the SHA-256 of the DER certificate the helper posted in round 1 (hash algorithm absent, meaning the sha256 default, or explicitly sha256). When the job description carried `expectedCertificateSha256`, that is the same value.
5. No other attributes are present except `signingTime` (1.2.840.113549.1.9.5) and CMS algorithm protection (1.2.840.113549.1.9.52), each at most once with exactly one value; any other OID is refused.
6. The encoding is strict DER: minimal lengths, primitive tags where DER requires them, attributes in ascending byte order inside the SET OF, no trailing bytes.

On any failure, for any document, the helper MUST report a failure (section 8.7), show a dialog, and sign none of the documents.

After login, the helper MUST sign with the private key that belongs to the posted certificate, and MUST refuse if the token holds no such key.

## 11. Algorithms

### 11.1 Keys, digests and schemes

| Key | `digestAlgorithm` | `signatureAlgorithm` | Signature encoding |
| --- | --- | --- | --- |
| RSA | `sha256` chosen by the server; the helper accepts `sha256` or `sha384` | `rsa-pkcs1-v1_5` or `rsa-pss` | Octet string of the modulus length (RFC 8017 I2OSP) |
| EC P-256 | `sha256` | `ecdsa` | DER `ECDSA-Sig-Value` |
| EC P-384 | `sha384` | `ecdsa` | DER `ECDSA-Sig-Value` |

Any other key type or curve is unsupported. The server MUST NOT prepare a signature for it, and the helper MUST NOT offer its certificate. P-256 requires `sha256` and P-384 requires `sha384`; the helper MUST refuse any other pairing, and MUST refuse `ecdsa` with an RSA key or an RSA scheme with an EC key.

Each signature is computed over the exact `toSign` bytes of its document: the input to the digest is the DER SignedAttributes with outer tag 0x31.

- **RSA PKCS#1 v1.5**: RSASSA-PKCS1-v1_5 (RFC 8017) with `digestAlgorithm`.
- **RSA-PSS**: RSASSA-PSS (RFC 8017) with `digestAlgorithm` as the message digest, MGF1 with the same digest, salt length equal to the digest length (32 for sha256, 48 for sha384), and trailer field 1.
- **ECDSA**: ECDSA over the digest of `toSign`. The raw `r || s` value from the token MUST be exactly twice the field length (64 bytes for P-256, 96 for P-384); the helper encodes it as DER `ECDSA-Sig-Value` (SEQUENCE of two minimal INTEGERs). The helper MUST NOT send raw `r || s`, and the server MUST refuse it.

The helper MUST read the key type from the token's key object and cross-check it with the certificate's SubjectPublicKeyInfo.

Informative, PKCS#11 mechanisms: `CKM_SHA256_RSA_PKCS` or `CKM_SHA384_RSA_PKCS` over `toSign` (the token hashes); `CKM_SHA256_RSA_PKCS_PSS` or `CKM_SHA384_RSA_PKCS_PSS` with matching `CK_RSA_PKCS_PSS_PARAMS`; `CKM_ECDSA` over the digest the helper computes.

### 11.2 Rollout

Informative: the helper and the signing service support RSA PKCS#1 v1.5, RSA-PSS and ECDSA, and the end-to-end CI signs a PDF with each through the reference server. A helper that does not support the `signatureAlgorithm` it receives MUST report a failure without signing, at the same point as a failed validation (section 8.3).

## 12. Helper UI requirements

### 12.1 Sign jobs

The helper MUST first try to enumerate certificates without logging in to the token, using the PKCS#11 public objects. If at least one candidate certificate is visible, the flow is:

1. Post the certificate (section 8.3), receive every document's `toSign`, validate them (sections 10 and 11), and download and check every document (section 8.4).
2. Show, in one view, before asking for the PIN:
   - the origin, with its host in ASCII (A-label) form;
   - the `title`;
   - the `signer`;
   - for a job with several documents, their number, and each document's `title` in order;
   - the subject of the certificate it will sign with;
   - each document's `messageDigest` from its `toSign`, as lowercase hex, beside that document's `title` when there are several.
3. Ask for the PIN once, log in, and sign every document in the same token session.

If the token exposes no certificate before login, the helper MAY ask for the PIN first. In that case:

1. The PIN prompt MUST show the origin, with its host in ASCII (A-label) form, the `title`, the `signer` and, for a job with several documents, their number and titles, and MUST state that the document digests will be shown for confirmation before signing.
2. After login the helper enumerates certificates (section 8.2 step 2), posts the chosen one (section 8.3), receives and validates every `toSign` (sections 10 and 11), and downloads and checks every document (section 8.4).
3. The helper MUST then show a second prompt with the certificate subject and every document's `messageDigest` as lowercase hex, and MUST require one explicit confirmation before signing the documents.
4. If the user declines, the helper MUST close the token session (logout) and report a failure (section 8.7).

In both paths the PIN is not retained beyond the login call (section 12.3), and the user approves the documents together: there is one PIN prompt or confirmation per job, not per document. Any validation failure in either path is reported and stops the job without signing any document.

In either path, a view MAY keep the document titles, the certificate subject and the digests behind a control in the same view that reveals them, provided the number of documents is shown without it.

On Windows, when the helper falls back to CNG, the vendor's PIN dialog is accepted; the helper MUST show the items of the first path's step 2 before handing off to it, and SHOULD sign every document through one key handle, so that a provider that keeps a handle authenticated asks for the PIN once per job. A provider that asks for the PIN on every signature by its own policy shows its dialog once per document.

### 12.2 Enrol jobs

Before asking for a PIN or reading certificates, the helper MUST show the origin, the `title` and the `signer`.

### 12.3 PIN handling

- The helper asks for the PIN once per job, whatever the number of documents, and MUST NOT retry a PIN automatically.
- The helper SHOULD show the remaining retry count where the driver exposes it.
- For tokens with a PIN pad, the helper MUST use the protected authentication path.
- The PIN MUST NOT leave the helper: it is never sent over the network, written to disk or logged, and the helper clears it from memory after login.

### 12.4 Text from the server

`title`, `signer`, document titles, error messages and the manifest `name` are untrusted. The helper MUST render them as plain text, MUST NOT interpret markup or links in them, and SHOULD neutralise bidirectional control characters. They MUST NOT replace or obscure the origin.

### 12.5 Branding

See section 6.4. The first-contact prompt shows the origin only.

## 13. Helper distribution: update manifest

This section covers helper distribution and is not integrator-facing. It is versioned separately from the protocol by its own `format` member.

Each release publishes two files in the KeySeal GitHub release:

- `keyseal-update.json`: the update manifest.
- `keyseal-update.json.sig`: its signatures.

```json
{
  "format": 1,
  "version": "1.4.0",
  "platforms": {
    "macos-universal": { "file": "keyseal-helper-1.4.0-macos-universal.zip", "sha256": "<hex>" },
    "windows-x64": { "file": "keyseal-helper-1.4.0-windows-x64.exe", "sha256": "<hex>" },
    "linux-x64": { "file": "keyseal-helper-1.4.0-linux-x64.AppImage", "sha256": "<hex>" }
  }
}
```

```json
{ "signatures": [ { "keyId": "<hex>", "signature": "<base64>" } ] }
```

- Each signature is Ed25519 over the exact bytes of `keyseal-update.json`. `keyId` is the lowercase hex SHA-256 of the raw 32-byte public key.
- The helper pins a set of public keys and a threshold. It MUST accept the manifest only if signatures from at least the threshold number of distinct pinned keys verify under strict Ed25519 verification. Signatures from unknown keys are ignored. The threshold is 1 until a second maintainer exists.
- The helper MUST refuse a `format` other than `1`, and MUST update only to a `version` higher than its own by SemVer precedence.
- The helper downloads the `file` for its platform and MUST install it only if its SHA-256 equals `sha256`. A platform without an entry does not update.
- The helper checks at most once a day, with a 5 second budget for the manifest, plus on `426` (section 7.3). Downloads run in the background after a job and apply on the next launch.

The driver catalogue is signed with a separate key and is outside this document.

## 14. Security considerations

- **Phishing origins.** Any web page can open a `keyseal://` link. First contact with an origin requires the user's approval, and that prompt shows only the origin so a manifest cannot dress up an unknown site. Users still have to judge the domain they see.
- **Token single use.** The token claims the job once. After the claim, every request for the job, including the document download, needs the claim nonce, which only the claiming helper received. A leaked link, from browser history or OS logs, cannot be used to take over a claimed job, and every token expires within 15 minutes.
- **Hashing at rest.** Servers store only the SHA-256 of the token, so a database read does not yield usable links. Tokens have at least 128 bits of entropy, so a single unsalted hash is sufficient.
- **Replay.** A claim nonce is bound to one job and one claim. The settle lease and the state machine make a repeated `POST` either a no-op answered from the job's state or a takeover of a lapsed lease; neither applies a signature twice.
- **Rate limiting.** Servers SHOULD rate limit job endpoint requests per client address and answer `429`. Token entropy makes guessing infeasible; the limit protects the server and the signing service.
- **The PIN.** The PIN never leaves the helper (section 12.3). The server never sees it and cannot ask for it.
- **Substituted attributes.** The helper validates SignedAttributes before the user confirms the digest and before signing (section 10), so a server cannot get a signature over attributes that bind a different certificate, carry no message digest, or smuggle extra attributes.
- **Cross-origin redirects and private addresses.** The helper refuses cross-origin redirects (section 4.3) and private, loopback and link-local addresses, including after DNS changes (section 4.2), so a trusted origin cannot steer the helper to another host or into the user's network.
- **Swapped signer.** Someone with an account at a trusted origin could create a job and get another person to open its link. The helper shows `title` and `signer`, and `expectedCertificateSha256` limits the job to one certificate. Integrators SHOULD set `expectedCertificateSha256` on sign jobs. Where no certificate is known yet, as on enrolment or a first signature, `certificatePolicy` narrows the job to certificates of a class, an issuer or an organization; it does not tie the job to one person.
- **What WYSIWYS guarantees.** The `messageDigest` alone ties the signature to a specific byte sequence but cannot be checked by eye against a document. With document download (section 8.4), the helper confirms for every document that the signature covers every byte of the PDF it downloaded except the signature value, and that those bytes hash to that document's `messageDigest`. It does not render the PDF, so it does not show the user what the document says. A server that controls the origin can still serve a PDF whose content differs from what the page displayed; the guarantee is that the signed bytes are the downloaded bytes. Later incremental updates appended after signing, and PDF features that display content differently in different viewers, are outside the check.
- **Batches.** The signer approves the documents of a job together, with one PIN entry, after seeing their number and titles; a server could pad a batch with a document the signer would not have signed alone. The cap of 20 documents keeps the list readable, every document is checked as section 8.4 says, and a server that refuses or cannot finish one document hands the integrator none, so a batch is never completed in part.
- **Insecure development origins.** `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` allows plain HTTP to loopback only, never persists trust, and is shown in a banner. It MUST NOT be set on a user's machine outside development and CI.
- **Driver selection.** Manifests and job responses cannot select PKCS#11 modules (section 6.3), so a server cannot make the helper load a library of its choosing.

## Appendix A. Example sign exchange (informative)

```http
GET /api/keyseal/v1/jobs/q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk HTTP/1.1
Host: dash.example.org
X-KeySeal-Version: 1.0.0

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"kind":"sign","title":"Board pack, 2 documents","signer":"Asha Rao",
 "claimNonce":"Zx8m_Q2...","expectedCertificateSha256":"9f86d0...","digestAlgorithm":"sha256",
 "documents":[
  {"title":"Board resolution 2026/14",
   "document":"https://dash.example.org/api/keyseal/v1/jobs/q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk/documents/0"},
  {"title":"Minutes of 12 March 2026",
   "document":"https://dash.example.org/api/keyseal/v1/jobs/q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk/documents/1"}]}
```

```http
POST /api/keyseal/v1/jobs/q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk/certificate HTTP/1.1
Content-Type: application/json
X-KeySeal-Version: 1.0.0

{"claimNonce":"Zx8m_Q2...","certificate":"MIIF...","chain":["MIIE..."]}

HTTP/1.1 200 OK

{"digestAlgorithm":"sha256","signatureAlgorithm":"rsa-pkcs1-v1_5",
 "documents":[{"toSign":"MYIB..."},{"toSign":"MYIC..."}]}
```

```http
POST /api/keyseal/v1/jobs/q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk/signature HTTP/1.1
Content-Type: application/json
X-KeySeal-Version: 1.0.0

{"claimNonce":"Zx8m_Q2...","signatures":["kQ3v...","Lp0a..."]}

HTTP/1.1 200 OK

{}
```

## Appendix B. Page status conventions (informative)

Job creation and the page's progress endpoint are outside this specification. The KeySeal packages agree on one shape so that `@keyseal/browser` can watch any `@keyseal/server` integration:

- A status response is a JSON object `{ "state": <job state>, "message"?: <string> }`, where `state` is one of the states in section 9 and `message`, present only when `state` is `failed` or `expired`, carries the reason for the user.
- A server-sent events stream, where offered, emits events named `state` whose data is that same JSON object, and ends after a terminal state.

Integrators with an existing status shape map it to this one in `getStatus`.
