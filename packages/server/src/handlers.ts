import {
  acceptCertificate,
  inspect,
  trustCertificate,
} from "./certificate-checks.js";
import {
  digestFor,
  schemeFor,
  type CertificateInspector,
} from "./certificates.js";
import {
  fromBase64,
  randomToken,
  sha256Hex,
  timingSafeEqual,
} from "./encoding.js";
import { isObject } from "./job-input.js";
import { JobRefused, type KeySealOptions } from "./keyseal.js";
import {
  error,
  json,
  NEEDS,
  readJson,
  readSubmission,
  TOKEN,
} from "./requests.js";
import { compareSemver, parseSemver } from "./semver.js";
import {
  preparedDocument,
  ServiceError,
  type SigningService,
} from "./service.js";
import {
  BUSY,
  gone,
  isExpired,
  isTerminal,
  leaseHeld,
  NOT_FOUND,
  pdfKey,
  type Transitions,
} from "./transitions.js";
import type { Adapter, Job, JobDocument } from "./types.js";

const UPGRADE_MESSAGE = "Update the signing helper, then try again.";

export type Action =
  | "claim"
  | "certificate"
  | "signature"
  | "failure"
  | "document";

export interface HandlerContext {
  options: KeySealOptions;
  adapter: Adapter;
  service: SigningService;
  inspector: CertificateInspector;
  clock: () => Date;
  minVersion: ReturnType<typeof parseSemver>;
  jobUrl: (token: string) => string;
  transitions: Transitions;
}

/** The job endpoint's requests (protocol section 8). */
export function createHandlers({
  options,
  adapter,
  service,
  inspector,
  clock,
  minVersion,
  jobUrl,
  transitions,
}: HandlerContext) {
  const {
    answerCurrent,
    deleteBlobs,
    deleteStates,
    fail,
    refuse,
    settle,
    withLease,
  } = transitions;

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

  async function nonceMatches(job: Job, claimNonce: string): Promise<boolean> {
    return timingSafeEqual(
      await sha256Hex(claimNonce),
      job.claimNonceHash ?? ""
    );
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
    const facts = await acceptCertificate(
      inspector,
      service,
      job,
      certificate,
      chain,
      now
    );
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
    const inspected = await inspect(
      inspector,
      job.certificate ?? "",
      job.chain ?? []
    );
    if (!job.stateKey || typeof inspected === "string") {
      throw new Error(`The signing state of job ${job.id} is missing`);
    }
    const certificate = fromBase64(inspected.der);
    const algorithm = schemeFor(inspected.key, job.rsaPadding);
    const digest = digestFor(inspected.key);
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
    // Again, for the facts the integrator gets: the round 1 answer isn't kept,
    // and a revocation found since refuses the certificate now.
    const facts = await trustCertificate(service, job, inspected);
    if (typeof facts === "string") {
      return await refuse(job, lease, facts);
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

  return handleJob;
}
