import {
  digestFor,
  schemeFor,
  type CertificateInspector,
} from "./certificates.js";
import {
  fromBase64,
  isBase64,
  randomToken,
  readBody,
  sha256Hex,
  timingSafeEqual,
} from "./encoding.js";
import { nodeCertificateInspector } from "./node-certificates.js";
import { compareSemver, parseSemver } from "./semver.js";
import {
  MAX_PDF_BYTES,
  preparedDocument,
  ServiceError,
  type ServiceClient,
} from "./service.js";
import type {
  Adapter,
  CertificateFacts,
  CertificatePolicy,
  DigestAlgorithm,
  Job,
  JobDocument,
  JobFailure,
  JobPatch,
  JobState,
  JobStatus,
  RsaPadding,
  SignatureDetails,
} from "./types.js";

/** Protocol section 9.2: a job expires this long after creation, whatever its state. */
export const JOB_TTL_MS = 15 * 60 * 1000;
/** Protocol section 9.3: a settle lease older than this may be taken over. */
export const SETTLE_LEASE_MS = 5 * 60 * 1000;
/** Protocol section 8.1. */
export const MAX_BODY_BYTES = 262_144;
/** Protocol section 8.2: a sign job's documents. */
export const MAX_DOCUMENTS = 20;
/**
 * The PDFs of one sign job together. Protocol section 8.4 caps the prepared
 * documents at 256 MiB; this leaves room for what preparing adds to each.
 */
export const MAX_JOB_PDF_BYTES = 240 * 1024 * 1024;

const TOKEN = /^[A-Za-z0-9_-]{20,128}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const FIELD_NAME = /^[A-Za-z0-9_]{1,64}$/;
const ACCENT_COLOR = /^#[0-9A-Fa-f]{6}$/;
// Unreserved characters only: the helper compares the document URL with
// the job URL it parsed, which re-encodes anything else.
const BASE_PATH = /^(?:\/[A-Za-z0-9._~-]+)*$/;
const MAX_CERTIFICATE_LENGTH = 16_384;
const MAX_CHAIN = 8;
const MAX_SIGNATURE_LENGTH = 4096;
// Protocol section 8.2: dotted-decimal OIDs, and the certificate policy's limits.
const OID = /^[0-2](?:\.(?:0|[1-9][0-9]*))+$/;
const MAX_OID_LENGTH = 128;
const MAX_POLICY_ENTRIES = 16;

const UPGRADE_MESSAGE = "Update the signing helper, then try again.";
const EXPIRED_MESSAGE = "The signing link expired. Start again.";
const NOT_FOUND =
  "This signing link is not valid or has expired. Start again from the page.";
const BUSY = "This job is busy with another request. Try again shortly.";

/**
 * Thrown from `onCompleted` to refuse the result: the job fails with
 * `message`, which the helper gets with a 422 and the page in `status`.
 */
export class JobRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JobRefused";
  }
}

export interface KeySealOptions {
  adapter: Adapter;
  service: ServiceClient;
  /** Scheme, host and port of the job URLs, such as `https://dash.example.org`. */
  origin: string;
  /** Path the job endpoint is mounted under, such as `/api/keyseal`; empty by default. */
  basePath?: string;
  /** Accept `http://localhost` and `http://127.0.0.1` origins, for development and CI. */
  allowInsecureOrigin?: boolean;
  /** Lowest `X-KeySeal-Version` served (SemVer); older helpers get 426. */
  minHelperVersion?: string;
  /** Returns false to answer a job endpoint request with 429. */
  rateLimit?: (request: Request) => boolean | Promise<boolean>;
  now?: () => Date;
  /**
   * Served as `/.well-known/keyseal.json`; without it the manifest is 404.
   * `translucent: false` asks the helper for opaque job windows.
   */
  branding?: {
    name: string;
    icon?: string;
    accentColor?: string;
    translucent?: boolean;
  };
  certificateInspector?: CertificateInspector;
}

interface JobInput {
  /**
   * What is being signed or enrolled, 1 to 200 characters. For several
   * documents it describes them together, such as "Board pack, 12 documents".
   */
  title: string;
  /** Who is expected to sign, 1 to 200 characters. */
  signer: string;
  /** SHA-256 (hex, either case) of the only certificate the helper may use. */
  expectedCertificateSha256?: string;
  /**
   * Limits the job to certificates with one of these policy OIDs, issuer
   * CNs, or this subject O; every member given must hold. For enrolment and
   * first signatures, where no certificate can be pinned yet.
   */
  certificatePolicy?: CertificatePolicy;
  /** Handed back on the job in `onCompleted` and `status`. */
  reference?: string;
}

export interface SignDocumentInput {
  /** A PDF with an empty signature field `fieldName`, at most 25 MiB. */
  pdf: Uint8Array;
  fieldName: string;
  /**
   * Shown to the signer, 1 to 200 characters. Required when the job has
   * several documents; a single document takes the job's title by default.
   */
  title?: string;
  /** The signing service's stamp style; its default otherwise. */
  stampStyle?: string;
  /** Written into the signature dictionary; each 1 to 200 characters, trimmed, without control characters. */
  signatureDetails?: SignatureDetails;
}

export interface SignJobInput extends JobInput {
  /** 1 to 20 documents, signed together; at most 240 MiB of PDF together. */
  documents: SignDocumentInput[];
  /** Announce the digest in the job description; the certificate must sign with it. */
  digestAlgorithm?: DigestAlgorithm;
  /** RSA keys sign with PKCS#1 v1.5 unless this is `pss`. */
  rsaPadding?: RsaPadding;
}

export type EnrolJobInput = JobInput;

export interface CreatedJob {
  /** The job's id, the SHA-256 of its token; pass it to `status`. */
  id: string;
  /** The raw job token, also the last segment of `jobUrl`; only its hash is stored. */
  token: string;
  /** The `keyseal://` link the page opens. */
  link: string;
  jobUrl: string;
}

export interface KeySeal {
  /** Answers the manifest and job endpoint requests; 404 for anything else. */
  handle(request: Request): Promise<Response>;
  createSignJob(input: SignJobInput): Promise<CreatedJob>;
  createEnrolJob(input: EnrolJobInput): Promise<CreatedJob>;
  /** Null for a malformed or unknown id. */
  status(id: string): Promise<JobStatus | null>;
  manifest(): Response;
}

type Action = "claim" | "certificate" | "signature" | "failure" | "document";

function json(body: object, status = 200): Response {
  return Response.json(body, {
    headers: { "Cache-Control": "no-store" },
    status,
  });
}

function error(status: number, message: string): Response {
  return json({ message }, status);
}

function isTerminal(job: Job): boolean {
  return job.state === "completed" || job.state === "failed";
}

function isExpired(job: Job, now: Date): boolean {
  if (job.state === "expired") {
    return true;
  }
  return (
    !isTerminal(job) && now.getTime() - job.createdAt.getTime() >= JOB_TTL_MS
  );
}

function gone(job: Job): Response {
  return error(
    410,
    job.state === "completed"
      ? "This job is already complete."
      : "This job has already ended. Start again from the page."
  );
}

function pdfKey(id: string, index: number): string {
  return `${id}/pdf/${index}`;
}

/** Protocol section 1: lengths in characters count Unicode code points. */
function characters(value: string): number {
  return [...value].length;
}

function checkText(name: string, value: unknown, max: number): void {
  const length = typeof value === "string" ? characters(value) : 0;
  if (length < 1 || length > max) {
    throw new TypeError(`${name} must be 1 to ${max} characters`);
  }
}

function checkList(
  name: string,
  value: unknown,
  check: (item: unknown) => boolean,
  each: string
): void {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > MAX_POLICY_ENTRIES ||
    !value.every(check)
  ) {
    throw new TypeError(
      `${name} must be a list of 1 to ${MAX_POLICY_ENTRIES} entries, each ${each}`
    );
  }
}

/** Protocol section 8.2: a copy of the policy with only its known members. */
function checkPolicy(policy: unknown): CertificatePolicy {
  if (!isObject(policy)) {
    throw new TypeError("certificatePolicy must be an object");
  }
  const { policyOids, issuerCommonNames, subjectOrganization } = policy;
  const checked: CertificatePolicy = {};
  if (policyOids !== undefined) {
    checkList(
      "certificatePolicy.policyOids",
      policyOids,
      (oid) =>
        typeof oid === "string" &&
        oid.length <= MAX_OID_LENGTH &&
        OID.test(oid),
      `a dotted-decimal OID of at most ${MAX_OID_LENGTH} characters`
    );
    checked.policyOids = [...(policyOids as string[])];
  }
  if (issuerCommonNames !== undefined) {
    checkList(
      "certificatePolicy.issuerCommonNames",
      issuerCommonNames,
      (name) =>
        typeof name === "string" &&
        characters(name) >= 1 &&
        characters(name) <= 200,
      "1 to 200 characters"
    );
    checked.issuerCommonNames = [...(issuerCommonNames as string[])];
  }
  if (subjectOrganization !== undefined) {
    checkText(
      "certificatePolicy.subjectOrganization",
      subjectOrganization,
      200
    );
    checked.subjectOrganization = subjectOrganization as string;
  }
  if (Object.keys(checked).length === 0) {
    throw new TypeError(
      "certificatePolicy needs policyOids, issuerCommonNames or subjectOrganization"
    );
  }
  return checked;
}

/**
 * Protocol section 8.2. The issuer CN comes from the certificate's issuer
 * name; the chain check to a trusted root (section 8.3) binds that name to
 * the CA that signed it.
 */
function satisfies(
  facts: CertificateFacts,
  policy: CertificatePolicy
): boolean {
  return (
    (policy.policyOids === undefined ||
      policy.policyOids.some((oid) => facts.policyOids.includes(oid))) &&
    (policy.issuerCommonNames === undefined ||
      (facts.issuerCommonName !== null &&
        policy.issuerCommonNames.includes(facts.issuerCommonName))) &&
    (policy.subjectOrganization === undefined ||
      facts.subjectOrganization === policy.subjectOrganization)
  );
}

const CONTROL = /\p{Cc}/u;

/** The given members trimmed, or null when none are. */
function checkSignatureDetails(
  value: unknown,
  name: string
): SignatureDetails | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  const given = value as Record<string, unknown>;
  const details: SignatureDetails = {};
  for (const member of ["reason", "location", "contactInfo"] as const) {
    const text = given[member];
    if (text === undefined) {
      continue;
    }
    const trimmed = typeof text === "string" ? text.trim() : "";
    checkText(`${name}.${member}`, trimmed, 200);
    if (CONTROL.test(trimmed)) {
      throw new TypeError(
        `${name}.${member} must not contain control characters`
      );
    }
    details[member] = trimmed;
  }
  return Object.keys(details).length > 0 ? details : null;
}

/** A sign job's documents as the job stores them; their PDFs become blobs. */
function checkDocuments(value: unknown, jobTitle: string): JobDocument[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > MAX_DOCUMENTS
  ) {
    throw new TypeError(
      `documents must be a list of 1 to ${MAX_DOCUMENTS} documents`
    );
  }
  let total = 0;
  const documents = value.map((entry: unknown, index): JobDocument => {
    const name = `documents[${index}]`;
    if (!isObject(entry)) {
      throw new TypeError(`${name} must be an object`);
    }
    const { fieldName, pdf, signatureDetails, stampStyle } = entry;
    if (typeof fieldName !== "string" || !FIELD_NAME.test(fieldName)) {
      throw new TypeError(
        `${name}.fieldName must be 1 to 64 letters, digits or underscores`
      );
    }
    if (!(pdf instanceof Uint8Array)) {
      throw new TypeError(`${name}.pdf must be a Uint8Array`);
    }
    if (pdf.byteLength > MAX_PDF_BYTES) {
      throw new TypeError(`${name}.pdf must be at most 25 MiB`);
    }
    total += pdf.byteLength;
    if (stampStyle !== undefined) {
      checkText(`${name}.stampStyle`, stampStyle, 64);
    }
    const title = entry.title ?? (value.length === 1 ? jobTitle : undefined);
    if (title === undefined) {
      throw new TypeError(
        `${name}.title is required when a job has several documents`
      );
    }
    checkText(`${name}.title`, title, 200);
    return {
      fieldName,
      signatureDetails:
        signatureDetails === undefined
          ? null
          : checkSignatureDetails(signatureDetails, `${name}.signatureDetails`),
      stampStyle: (stampStyle as string | undefined) ?? null,
      title: title as string,
      toSign: null,
    };
  });
  if (total > MAX_JOB_PDF_BYTES) {
    throw new TypeError("documents must hold at most 240 MiB of PDF together");
  }
  return documents;
}

/** WHATWG URL serialises every IP host as dotted decimal or bracketed IPv6. */
function isIpLiteral(hostname: string): boolean {
  return hostname.startsWith("[") || /^[0-9.]+$/.test(hostname);
}

function isLocalhost(hostname: string): boolean {
  return hostname === "localhost" || hostname.endsWith(".localhost");
}

function escapeRegExp(value: string): string {
  return value.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSignature(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_SIGNATURE_LENGTH &&
    isBase64(value)
  );
}

function isCertificate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_CERTIFICATE_LENGTH &&
    isBase64(value)
  );
}

type Submission =
  | {
      action: "certificate";
      claimNonce: string;
      certificate: string;
      chain: string[];
    }
  | { action: "signature"; claimNonce: string; signatures: string[] }
  | { action: "failure"; claimNonce: string; message: string };

/** Protocol section 9.2: the states each POST needs. */
const NEEDS: Record<Submission["action"], JobState[]> = {
  certificate: ["claimed"],
  failure: ["claimed", "prepared"],
  signature: ["prepared"],
};

/** Reads a POST body as JSON: the parsed value, or the 413 or 422 response. */
async function readJson(request: Request): Promise<unknown> {
  if (Number(request.headers.get("Content-Length") ?? "0") > MAX_BODY_BYTES) {
    return error(413, "The request is too large.");
  }
  const bytes = await readBody(request.body, MAX_BODY_BYTES);
  if (!bytes) {
    return error(413, "The request is too large.");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return error(422, "The request is not valid JSON.");
  }
}

/**
 * Reads and checks a POST body: the submission, or the 413 or 422 response.
 * A signature submission must carry one signature per document.
 */
async function readSubmission(
  request: Request,
  action: Submission["action"],
  documents: number
): Promise<Submission | Response> {
  const body = await readJson(request);
  if (body instanceof Response) {
    return body;
  }
  if (
    !isObject(body) ||
    typeof body.claimNonce !== "string" ||
    !TOKEN.test(body.claimNonce)
  ) {
    return error(422, "The request has no valid claimNonce.");
  }
  const { claimNonce } = body;
  if (action === "certificate") {
    const { certificate, chain } = body;
    if (
      isCertificate(certificate) &&
      Array.isArray(chain) &&
      chain.length <= MAX_CHAIN &&
      chain.every(isCertificate)
    ) {
      return { action, certificate, chain, claimNonce };
    }
    return error(
      422,
      "The request needs a certificate and a chain of base64 DER certificates."
    );
  }
  if (action === "signature") {
    const { signatures } = body;
    if (
      Array.isArray(signatures) &&
      signatures.length === documents &&
      signatures.every(isSignature)
    ) {
      return { action, claimNonce, signatures };
    }
    return error(
      422,
      "The request needs one base64 signature per document, in order."
    );
  }
  const message = typeof body.message === "string" ? body.message.trim() : "";
  const length = characters(message);
  if (length >= 1 && length <= 500) {
    return { action, claimNonce, message };
  }
  return error(422, "The request needs a message of 1 to 500 characters.");
}

export function createKeySeal(options: KeySealOptions): KeySeal {
  const { adapter, service } = options;
  const inspector = options.certificateInspector ?? nodeCertificateInspector;
  const clock = options.now ?? (() => new Date());
  const basePath = options.basePath ?? "";

  // Protocol section 4: the helper refuses any other origin.
  const origin = new URL(options.origin);
  const { hostname } = origin;
  const insecure =
    options.allowInsecureOrigin === true &&
    origin.protocol === "http:" &&
    (hostname === "localhost" || hostname === "127.0.0.1");
  if (
    origin.origin !== options.origin ||
    !(
      insecure ||
      (origin.protocol === "https:" &&
        !isIpLiteral(hostname) &&
        !isLocalhost(hostname))
    )
  ) {
    throw new TypeError(
      "origin must be a bare https origin on a domain name, such as https://example.org"
    );
  }
  if (!BASE_PATH.test(basePath)) {
    throw new TypeError(
      "basePath must be empty or /-separated segments of letters, digits, . _ ~ and -"
    );
  }
  const minVersion =
    options.minHelperVersion === undefined
      ? null
      : parseSemver(options.minHelperVersion);
  if (options.minHelperVersion !== undefined && !minVersion) {
    throw new TypeError("minHelperVersion must be a SemVer version");
  }
  const { branding } = options;
  if (branding) {
    checkText("branding.name", branding.name, 64);
    if (
      branding.icon !== undefined &&
      new URL(branding.icon).origin !== options.origin
    ) {
      throw new TypeError(
        "branding.icon must be an absolute URL on the origin"
      );
    }
    if (
      branding.accentColor !== undefined &&
      !ACCENT_COLOR.test(branding.accentColor)
    ) {
      throw new TypeError("branding.accentColor must be #rrggbb");
    }
    if (
      branding.translucent !== undefined &&
      typeof branding.translucent !== "boolean"
    ) {
      throw new TypeError("branding.translucent must be a boolean");
    }
  }

  const jobsPath = `${basePath}/v1/jobs`;
  const route = new RegExp(
    `^${escapeRegExp(jobsPath)}/([^/]+)(?:/(certificate|signature|failure)|/documents/(0|[1-9][0-9]*))?$`
  );

  function jobUrl(token: string): string {
    return `${options.origin}${jobsPath}/${token}`;
  }

  /** The signing service's states under `stateKey`, one per document. */
  async function deleteStates(stateKey: string, count: number): Promise<void> {
    for (let index = 0; index < count; index += 1) {
      await adapter.deleteBlob(`${stateKey}/${index}`);
    }
  }

  async function deleteBlobs(job: Job): Promise<void> {
    for (let index = 0; index < job.documents.length; index += 1) {
      await adapter.deleteBlob(pdfKey(job.id, index));
    }
    if (job.stateKey) {
      await deleteStates(job.stateKey, job.documents.length);
    }
  }

  /** The answer for a job whose state moved under this request. */
  async function answerCurrent(id: string): Promise<Response> {
    const job = await adapter.get(id);
    if (!job || isExpired(job, clock())) {
      return error(404, NOT_FOUND);
    }
    if (isTerminal(job)) {
      return gone(job);
    }
    return error(409, BUSY);
  }

  /** Applies `patch` and frees the lease, only while this request holds it. */
  async function settle(
    job: Job,
    lease: Date,
    patch: JobPatch
  ): Promise<boolean> {
    return await adapter.transition(
      job.id,
      { leaseStartedAt: lease, state: job.state },
      { ...patch, leaseStartedAt: null }
    );
  }

  /** Tells the integrator, then fails the job; false if it moved under `lease`. */
  async function fail(
    job: Job,
    lease: Date,
    failure: JobFailure
  ): Promise<boolean> {
    try {
      await adapter.onFailed?.(job, failure);
    } catch (cause) {
      console.error(`keyseal: onFailed failed for job ${job.id}`, cause);
    }
    if (
      !(await settle(job, lease, { error: failure.message, state: "failed" }))
    ) {
      return false;
    }
    await deleteBlobs(job);
    return true;
  }

  /** 422 for a refused certificate or signature; the job fails with the same message. */
  async function refuse(
    job: Job,
    lease: Date,
    message: string
  ): Promise<Response> {
    if (!(await fail(job, lease, { message, reportedBy: "server" }))) {
      return await answerCurrent(job.id);
    }
    return error(422, message);
  }

  /**
   * Protocol section 8.8: a service 400 or 422 refuses and fails the job, as
   * does `JobRefused` from `onCompleted`; anything else leaves it for a retry.
   */
  async function serviceFailed(
    job: Job,
    lease: Date,
    cause: unknown
  ): Promise<Response> {
    if (cause instanceof JobRefused) {
      return await refuse(job, lease, cause.message);
    }
    if (!(cause instanceof ServiceError)) {
      throw cause;
    }
    if (cause.status === 400 || cause.status === 422) {
      // The service's message reaches the helper and the page; bounded like
      // a failure report (section 8.7).
      const message = [...cause.message.trim()].slice(0, 500).join("");
      return await refuse(
        job,
        lease,
        message || "The signing service refused."
      );
    }
    return error(502, "The signing service is unavailable. Try again.");
  }

  /**
   * Runs `work` under the settle lease (protocol section 9.3). Whatever
   * `work` leaves unchanged gets the lease back.
   */
  async function withLease(
    job: Job,
    now: Date,
    work: (lease: Date) => Promise<Response>
  ): Promise<Response> {
    const lease = now;
    const acquired = await adapter.transition(
      job.id,
      { leaseStartedAt: job.leaseStartedAt, state: job.state },
      { leaseStartedAt: lease }
    );
    if (!acquired) {
      return error(409, BUSY);
    }
    try {
      return await work(lease);
    } finally {
      await adapter.transition(
        job.id,
        { leaseStartedAt: lease, state: job.state },
        { leaseStartedAt: null }
      );
    }
  }

  /** Protocol section 9.3: a lease younger than 5 minutes cannot be taken over. */
  function leaseHeld(job: Job, now: Date): boolean {
    return (
      job.leaseStartedAt !== null &&
      now.getTime() - job.leaseStartedAt.getTime() <= SETTLE_LEASE_MS
    );
  }

  async function nonceMatches(job: Job, claimNonce: string): Promise<boolean> {
    return timingSafeEqual(
      await sha256Hex(claimNonce),
      job.claimNonceHash ?? ""
    );
  }

  async function inspect(
    der: string,
    chain: string[]
  ): Promise<CertificateFacts | string> {
    const bytes = fromBase64(der);
    const inspected = inspector.inspect(bytes);
    if (!inspected) {
      return "The certificate could not be read.";
    }
    if (!inspected.key) {
      return "The certificate's key is not supported. Use an RSA, P-256 or P-384 certificate.";
    }
    return {
      ...inspected,
      chain,
      der,
      key: inspected.key,
      sha256: await sha256Hex(bytes),
    };
  }

  /** Protocol section 8.3: the checks before the service prepares a signature. */
  async function acceptCertificate(
    job: Job,
    der: string,
    chain: string[],
    now: Date
  ): Promise<CertificateFacts | string> {
    const facts = await inspect(der, chain);
    if (typeof facts === "string") {
      return facts;
    }
    if (now < facts.notBefore || now >= facts.notAfter) {
      return "The certificate is not valid now.";
    }
    if (
      job.expectedCertificateSha256 &&
      facts.sha256 !== job.expectedCertificateSha256
    ) {
      return "This is not the certificate this job expects. Use the one registered for you.";
    }
    if (job.certificatePolicy && !satisfies(facts, job.certificatePolicy)) {
      return "This certificate is not one this job accepts. Use a certificate of the kind the job asks for.";
    }
    if (job.digestAlgorithm && digestFor(facts.key) !== job.digestAlgorithm) {
      return "The certificate's key does not match the digest this job announced.";
    }
    const { trusted } = await service.certificate({ certificate: der, chain });
    if (!trusted) {
      return "The certificate is not from a trusted certifying authority, or may not sign.";
    }
    return facts;
  }

  async function claim(job: Job, token: string): Promise<Response> {
    if (job.state !== "pending") {
      return error(409, "This job was already opened by a signing helper.");
    }
    const claimNonce = randomToken();
    const claimed = await adapter.transition(
      job.id,
      { leaseStartedAt: job.leaseStartedAt, state: "pending" },
      { claimNonceHash: await sha256Hex(claimNonce), state: "claimed" }
    );
    if (!claimed) {
      return await answerCurrent(job.id);
    }
    return json({
      claimNonce,
      kind: job.kind,
      signer: job.signer,
      title: job.title,
      ...(job.expectedCertificateSha256
        ? { expectedCertificateSha256: job.expectedCertificateSha256 }
        : {}),
      ...(job.certificatePolicy
        ? { certificatePolicy: job.certificatePolicy }
        : {}),
      ...(job.kind === "sign"
        ? {
            documents: job.documents.map(({ title }, index) => ({
              document: `${jobUrl(token)}/documents/${index}`,
              title,
            })),
          }
        : {}),
      ...(job.kind === "sign" && job.digestAlgorithm
        ? { digestAlgorithm: job.digestAlgorithm }
        : {}),
    });
  }

  async function submitCertificate(
    job: Job,
    { certificate, chain }: { certificate: string; chain: string[] },
    lease: Date,
    now: Date
  ): Promise<Response> {
    const facts = await acceptCertificate(job, certificate, chain, now);
    if (typeof facts === "string") {
      return await refuse(job, lease, facts);
    }
    if (job.kind === "enrol") {
      await adapter.onCompleted(job, { certificate: facts, kind: "enrol" });
      if (
        !(await settle(job, lease, { certificate, chain, state: "completed" }))
      ) {
        return await answerCurrent(job.id);
      }
      return json({});
    }
    const digestAlgorithm = digestFor(facts.key);
    const signatureAlgorithm = schemeFor(facts.key, job.rsaPadding);
    // Keyed by lease, so a request whose lease was taken over cannot replace the winner's states.
    const stateKey = `${job.id}/state/${lease.getTime()}`;
    const documents: JobDocument[] = [];
    try {
      for (const [index, entry] of job.documents.entries()) {
        const pdf = await adapter.getBlob(pdfKey(job.id, index));
        if (!pdf) {
          throw new Error(`The PDF of job ${job.id} is missing`);
        }
        const started = await service.signStart({
          certificate,
          chain,
          fieldName: entry.fieldName,
          pdf,
          ...(signatureAlgorithm === "rsa-pss" ? { rsaPadding: "pss" } : {}),
          ...(entry.stampStyle ? { stampStyle: entry.stampStyle } : {}),
          ...(entry.signatureDetails
            ? { signatureDetails: entry.signatureDetails }
            : {}),
        });
        if (
          started.digestAlgorithm !== digestAlgorithm ||
          started.signatureAlgorithm !== signatureAlgorithm
        ) {
          throw new Error(
            `The signing service chose ${started.digestAlgorithm} with ${started.signatureAlgorithm} for a ${digestAlgorithm} ${facts.key.type} key`
          );
        }
        await adapter.putBlob(
          `${stateKey}/${index}`,
          new TextEncoder().encode(started.state)
        );
        documents.push({ ...entry, toSign: started.toSign });
      }
    } catch (cause) {
      // Every document or none: the job stays claimed for a retry, or fails.
      await deleteStates(stateKey, job.documents.length);
      throw cause;
    }
    if (
      !(await settle(job, lease, {
        certificate,
        chain,
        documents,
        state: "prepared",
        stateKey,
      }))
    ) {
      await deleteStates(stateKey, documents.length);
      return await answerCurrent(job.id);
    }
    for (let index = 0; index < documents.length; index += 1) {
      await adapter.deleteBlob(pdfKey(job.id, index));
    }
    return json({
      digestAlgorithm,
      documents: documents.map(({ toSign }) => ({ toSign })),
      signatureAlgorithm,
    });
  }

  /**
   * Protocol section 8.5: every signature is verified before any document is
   * finished, and every document is finished, in memory, before the
   * integrator gets them, so a refusal or a lease takeover never hands over
   * part of a batch.
   */
  async function submitSignatures(
    job: Job,
    signatures: string[],
    lease: Date
  ): Promise<Response> {
    const facts = await inspect(job.certificate ?? "", job.chain ?? []);
    if (!job.stateKey || typeof facts === "string") {
      throw new Error(`The signing state of job ${job.id} is missing`);
    }
    const certificate = fromBase64(facts.der);
    const algorithm = schemeFor(facts.key, job.rsaPadding);
    const digest = digestFor(facts.key);
    for (const [index, signature] of signatures.entries()) {
      const toSign = job.documents[index]?.toSign;
      if (!toSign) {
        throw new Error(`The signing state of job ${job.id} is missing`);
      }
      const valid = inspector.verify(
        certificate,
        fromBase64(toSign),
        fromBase64(signature),
        algorithm,
        digest
      );
      if (!valid) {
        return await refuse(
          job,
          lease,
          "The signature doesn't match the certificate: was the right token used?"
        );
      }
    }
    // Read up front: a request that takes over the lease deletes them when it completes.
    const states: string[] = [];
    for (let index = 0; index < signatures.length; index += 1) {
      const state = await adapter.getBlob(`${job.stateKey}/${index}`);
      if (!state) {
        throw new Error(`The signing state of job ${job.id} is missing`);
      }
      states.push(new TextDecoder().decode(state));
    }
    const pdfs: Uint8Array[] = [];
    for (const [index, signature] of signatures.entries()) {
      pdfs.push(await service.signFinish({ signature, state: states[index]! }));
    }
    await adapter.onCompleted(job, { certificate: facts, kind: "sign", pdfs });
    if (!(await settle(job, lease, { state: "completed" }))) {
      return await answerCurrent(job.id);
    }
    await deleteBlobs(job);
    return json({});
  }

  /** Protocol section 8.4: the prepared document at `index`. */
  async function document(
    job: Job,
    request: Request,
    index: number
  ): Promise<Response> {
    const bearer =
      request.headers.get("Authorization")?.match(/^Bearer (\S+)$/)?.[1] ?? "";
    const claimNonce = request.headers.get("X-KeySeal-Claim") ?? "";
    const tokenMatches = timingSafeEqual(await sha256Hex(bearer), job.id);
    const nonceMatches = timingSafeEqual(
      await sha256Hex(claimNonce),
      job.claimNonceHash ?? ""
    );
    if (!(tokenMatches && nonceMatches)) {
      return error(
        403,
        "This request does not belong to the helper that opened the job."
      );
    }
    if (job.state !== "prepared") {
      return error(409, "The document is not ready yet.");
    }
    if (index >= job.documents.length) {
      return error(404, "This job has no such document.");
    }
    const state = job.stateKey
      ? await adapter.getBlob(`${job.stateKey}/${index}`)
      : null;
    const pdf = state
      ? preparedDocument(new TextDecoder().decode(state))
      : null;
    if (!pdf) {
      throw new Error(`The prepared document of job ${job.id} is missing`);
    }
    return new Response(pdf, {
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "application/pdf",
      },
    });
  }

  function helperTooOld(request: Request): boolean {
    if (!minVersion) {
      return false;
    }
    const version = parseSemver(request.headers.get("X-KeySeal-Version") ?? "");
    return !version || compareSemver(version, minVersion) < 0;
  }

  /**
   * Protocol section 7.3: whether a 426 also fails the job. Only a pending job,
   * or a POST from the helper that claimed it, so the token alone cannot end a
   * claimed job; never under a live lease.
   */
  async function outdatedFails(
    job: Job,
    request: Request,
    now: Date
  ): Promise<boolean> {
    if (isExpired(job, now) || isTerminal(job) || leaseHeld(job, now)) {
      return false;
    }
    if (job.state === "pending") {
      return true;
    }
    if (request.method !== "POST") {
      return false;
    }
    const body = await readJson(request);
    return (
      !(body instanceof Response) &&
      isObject(body) &&
      typeof body.claimNonce === "string" &&
      (await nonceMatches(job, body.claimNonce))
    );
  }

  /** Protocol section 7.3: fail the job too where allowed, so the page can show why. */
  async function refuseOutdated(
    id: string,
    request: Request,
    now: Date
  ): Promise<Response> {
    const job = await adapter.get(id);
    if (job && (await outdatedFails(job, request, now))) {
      await withLease(job, now, async (lease) => {
        await fail(job, lease, {
          message: UPGRADE_MESSAGE,
          reportedBy: "server",
        });
        return json({});
      });
    }
    return json(
      { message: UPGRADE_MESSAGE, minVersion: options.minHelperVersion },
      426
    );
  }

  /** Protocol section 8.1: the checks run in the order of its status list. */
  async function handleJob(
    request: Request,
    token: string,
    action: Action,
    index: number
  ): Promise<Response> {
    if (options.rateLimit && !(await options.rateLimit(request))) {
      return error(429, "Too many requests. Wait a minute, then try again.");
    }
    if (!TOKEN.test(token)) {
      return error(404, NOT_FOUND);
    }
    const now = clock();
    const id = await sha256Hex(token);
    if (helperTooOld(request)) {
      return await refuseOutdated(id, request, now);
    }
    const job = await adapter.get(id);
    if (!job || isExpired(job, now)) {
      return error(404, NOT_FOUND);
    }
    if (isTerminal(job)) {
      return gone(job);
    }
    if (action === "claim") {
      return await claim(job, token);
    }
    if (action === "document") {
      return await document(job, request, index);
    }
    const submission = await readSubmission(
      request,
      action,
      job.documents.length
    );
    if (submission instanceof Response) {
      return submission;
    }
    if (!(await nonceMatches(job, submission.claimNonce))) {
      return error(
        409,
        "This request does not belong to the helper that opened the job."
      );
    }
    if (!NEEDS[submission.action].includes(job.state)) {
      return error(409, "This job is not waiting for that request.");
    }
    if (leaseHeld(job, now)) {
      return error(409, BUSY);
    }
    return await withLease(job, now, async (lease) => {
      if (submission.action === "failure") {
        return (await fail(job, lease, {
          message: submission.message,
          reportedBy: "helper",
        }))
          ? json({})
          : await answerCurrent(job.id);
      }
      try {
        return submission.action === "certificate"
          ? await submitCertificate(job, submission, lease, now)
          : await submitSignatures(job, submission.signatures, lease);
      } catch (cause) {
        return await serviceFailed(job, lease, cause);
      }
    });
  }

  const manifestBody = branding
    ? {
        name: branding.name,
        protocol: 1,
        ...(branding.icon === undefined ? {} : { icon: branding.icon }),
        ...(branding.accentColor === undefined
          ? {}
          : { accentColor: branding.accentColor }),
        ...(branding.translucent === undefined
          ? {}
          : { translucent: branding.translucent }),
        ...(options.minHelperVersion === undefined
          ? {}
          : { minHelperVersion: options.minHelperVersion }),
      }
    : null;

  function manifest(): Response {
    return manifestBody
      ? Response.json(manifestBody)
      : error(404, "This origin has no manifest.");
  }

  async function createJob(
    input: JobInput,
    sign: Omit<SignJobInput, keyof JobInput> | null
  ): Promise<CreatedJob> {
    checkText("title", input.title, 200);
    checkText("signer", input.signer, 200);
    const expectedCertificateSha256 =
      typeof input.expectedCertificateSha256 === "string"
        ? input.expectedCertificateSha256.toLowerCase()
        : input.expectedCertificateSha256;
    if (
      expectedCertificateSha256 !== undefined &&
      !SHA256_HEX.test(expectedCertificateSha256)
    ) {
      throw new TypeError(
        "expectedCertificateSha256 must be 64 hex characters"
      );
    }
    const certificatePolicy =
      input.certificatePolicy === undefined
        ? null
        : checkPolicy(input.certificatePolicy);
    const documents = sign ? checkDocuments(sign.documents, input.title) : [];
    if (sign) {
      if (
        sign.digestAlgorithm !== undefined &&
        sign.digestAlgorithm !== "sha256" &&
        sign.digestAlgorithm !== "sha384"
      ) {
        throw new TypeError("digestAlgorithm must be sha256 or sha384");
      }
      if (
        sign.rsaPadding !== undefined &&
        sign.rsaPadding !== "pkcs1" &&
        sign.rsaPadding !== "pss"
      ) {
        throw new TypeError("rsaPadding must be pkcs1 or pss");
      }
    }
    const now = clock();
    for (const expired of await adapter.expireOlderThan(
      new Date(now.getTime() - JOB_TTL_MS),
      new Date(now.getTime() - SETTLE_LEASE_MS)
    )) {
      await deleteBlobs(expired);
    }
    const token = randomToken();
    const id = await sha256Hex(token);
    const job: Job = {
      certificate: null,
      chain: null,
      claimNonceHash: null,
      createdAt: now,
      digestAlgorithm: sign?.digestAlgorithm ?? null,
      documents,
      error: null,
      certificatePolicy,
      expectedCertificateSha256: expectedCertificateSha256 ?? null,
      id,
      kind: sign ? "sign" : "enrol",
      leaseStartedAt: null,
      reference: input.reference ?? null,
      rsaPadding: sign?.rsaPadding ?? "pkcs1",
      signer: input.signer,
      state: "pending",
      stateKey: null,
      title: input.title,
    };
    try {
      for (const [index, entry] of (sign?.documents ?? []).entries()) {
        await adapter.putBlob(pdfKey(id, index), entry.pdf);
      }
      await adapter.create(job);
    } catch (cause) {
      // The sweep only sees jobs that exist, so the blobs go now.
      for (let index = 0; index < documents.length; index += 1) {
        await adapter.deleteBlob(pdfKey(id, index)).catch(() => {});
      }
      throw cause;
    }
    const url = jobUrl(token);
    return {
      id,
      jobUrl: url,
      link: `keyseal://${sign ? "sign" : "enrol"}?job=${encodeURIComponent(url)}`,
      token,
    };
  }

  return {
    async createEnrolJob(input) {
      return await createJob(input, null);
    },

    async createSignJob(input) {
      const {
        title,
        signer,
        expectedCertificateSha256,
        certificatePolicy,
        reference,
        ...sign
      } = input;
      return await createJob(
        {
          signer,
          title,
          ...(expectedCertificateSha256 === undefined
            ? {}
            : { expectedCertificateSha256 }),
          ...(certificatePolicy === undefined ? {} : { certificatePolicy }),
          ...(reference === undefined ? {} : { reference }),
        },
        sign
      );
    },

    async handle(request) {
      const { pathname } = new URL(request.url);
      if (pathname === "/.well-known/keyseal.json") {
        return request.method === "GET" ? manifest() : error(404, "Not found.");
      }
      const match = route.exec(pathname);
      const action: Action =
        match?.[3] === undefined
          ? ((match?.[2] as Action | undefined) ?? "claim")
          : "document";
      const method =
        action === "claim" || action === "document" ? "GET" : "POST";
      if (!match || request.method !== method) {
        return error(404, "Not found.");
      }
      try {
        return await handleJob(request, match[1]!, action, Number(match[3]));
      } catch (cause) {
        // Errors name the job by its id, never by the token.
        console.error("keyseal: job request failed", cause);
        return error(500, "Something went wrong. Try again.");
      }
    },

    manifest,

    async status(id) {
      if (!SHA256_HEX.test(id)) {
        return null;
      }
      const job = await adapter.get(id);
      if (!job) {
        return null;
      }
      const expired = isExpired(job, clock());
      const message = expired ? EXPIRED_MESSAGE : job.error;
      return {
        expiresAt: new Date(job.createdAt.getTime() + JOB_TTL_MS),
        kind: job.kind,
        reference: job.reference,
        state: expired ? "expired" : job.state,
        ...(message === null ? {} : { message }),
      };
    },
  };
}
