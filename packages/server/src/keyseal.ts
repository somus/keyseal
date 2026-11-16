import { blobJobId, pdfKey } from "./blobs.js";
import { randomToken, sha256Hex } from "./encoding.js";
import { InvalidJobInput } from "./errors.js";
import { createHandlers, type Action } from "./handlers.js";
import {
  checkDocuments,
  checkPolicy,
  checkText,
  SHA256_HEX,
} from "./job-input.js";
import { JOB_TTL_MS, SETTLE_LEASE_MS } from "./limits.js";
import { nodeCertificateInspector } from "./node-certificates.js";
import { checkOptions, type KeySealOptions } from "./options.js";
import { error } from "./requests.js";
import { createTransitions, isExpired, isTerminal } from "./transitions.js";
import type {
  CertificatePolicy,
  DigestAlgorithm,
  Job,
  JobKind,
  JobStatus,
  RsaPadding,
  SignatureDetails,
} from "./types.js";

const EXPIRED_MESSAGE = "The signing link expired. Start again.";

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
   * CNs, or this subject O, and to the key usage asked for (nonRepudiation
   * by default); every member given must hold. For enrolment and first
   * signatures, where no certificate can be pinned yet.
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

/** What a sign job takes beyond `JobInput`. */
type SignFields = Omit<SignJobInput, keyof JobInput>;

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
  /**
   * Expires jobs past their TTL and deletes their blobs, and the blobs of
   * jobs that ended or are gone. Creating a job expires old ones too; call
   * this from a scheduler so a quiet deployment still cleans up.
   */
  sweep(): Promise<void>;
}

function escapeRegExp(value: string): string {
  return value.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

export function createKeySeal(options: KeySealOptions): KeySeal {
  const { adapter } = options;
  const inspector = options.certificateInspector ?? nodeCertificateInspector;
  const clock = options.now ?? (() => new Date());
  const basePath = options.basePath ?? "";
  const minVersion = checkOptions(options, basePath);
  const { branding } = options;

  const jobsPath = `${basePath}/v1/jobs`;
  const route = new RegExp(
    `^${escapeRegExp(jobsPath)}/(?<token>[^/]+)(?:/(?<action>certificate|signature|failure)|/documents/(?<index>0|[1-9][0-9]*))?$`
  );

  function jobUrl(token: string): string {
    return `${options.origin}${jobsPath}/${token}`;
  }

  const transitions = createTransitions(adapter, clock);
  const { deleteBlobs } = transitions;
  const handleJob = createHandlers({
    clock,
    inspector,
    jobUrl,
    minVersion,
    options,
    transitions,
  });

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

  async function expire(): Promise<void> {
    const now = clock();
    for (const expired of await adapter.expireOlderThan(
      new Date(now.getTime() - JOB_TTL_MS),
      new Date(now.getTime() - SETTLE_LEASE_MS)
    )) {
      await deleteBlobs(expired);
    }
  }

  async function createJob(
    kind: JobKind,
    input: JobInput & Partial<SignFields>
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
      throw new InvalidJobInput(
        "expectedCertificateSha256 must be 64 hex characters"
      );
    }
    const certificatePolicy =
      input.certificatePolicy === undefined
        ? null
        : checkPolicy(input.certificatePolicy);
    // An enrol job ignores the sign job's fields.
    const sign: Partial<SignFields> = kind === "sign" ? input : {};
    const documents =
      kind === "sign" ? checkDocuments(sign.documents, input.title) : [];
    if (
      sign.digestAlgorithm !== undefined &&
      sign.digestAlgorithm !== "sha256" &&
      sign.digestAlgorithm !== "sha384"
    ) {
      throw new InvalidJobInput("digestAlgorithm must be sha256 or sha384");
    }
    if (
      sign.rsaPadding !== undefined &&
      sign.rsaPadding !== "pkcs1" &&
      sign.rsaPadding !== "pss"
    ) {
      throw new InvalidJobInput("rsaPadding must be pkcs1 or pss");
    }
    await expire();
    const now = clock();
    const token = randomToken();
    const id = await sha256Hex(token);
    const job: Job = {
      certificate: null,
      chain: null,
      claimNonceHash: null,
      createdAt: now,
      digestAlgorithm: sign.digestAlgorithm ?? null,
      documents,
      error: null,
      certificatePolicy,
      expectedCertificateSha256: expectedCertificateSha256 ?? null,
      id,
      kind,
      leaseStartedAt: null,
      reference: input.reference ?? null,
      rsaPadding: sign.rsaPadding ?? "pkcs1",
      signer: input.signer,
      state: "pending",
      stateKey: null,
      title: input.title,
    };
    // The job first: a sweep deletes the blobs of a job it can't find, and
    // nobody has the token yet to use the job before its PDFs are stored.
    await adapter.create(job);
    for (const [index, entry] of (sign.documents ?? []).entries()) {
      await adapter.putBlob(pdfKey(id, index), entry.pdf);
    }
    const url = jobUrl(token);
    return {
      id,
      jobUrl: url,
      link: `keyseal://${kind}?job=${encodeURIComponent(url)}`,
      token,
    };
  }

  return {
    async createEnrolJob(input) {
      return await createJob("enrol", input);
    },

    async createSignJob(input) {
      return await createJob("sign", input);
    },

    async handle(request) {
      const { pathname } = new URL(request.url);
      if (pathname === "/.well-known/keyseal.json") {
        return request.method === "GET" ? manifest() : error(404, "Not found.");
      }
      const groups = route.exec(pathname)?.groups;
      const action: Action =
        groups?.index === undefined
          ? ((groups?.action as Action | undefined) ?? "claim")
          : "document";
      const method =
        action === "claim" || action === "document" ? "GET" : "POST";
      if (!groups || request.method !== method) {
        return error(404, "Not found.");
      }
      try {
        return await handleJob(
          request,
          groups.token!,
          action,
          Number(groups.index)
        );
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

    async sweep() {
      await expire();
      // A deletion that failed, or a request that stopped, after its job
      // ended leaves blobs that nothing else deletes. Open jobs keep theirs.
      const ended = new Map<string, boolean>();
      for (const key of await adapter.listBlobs()) {
        // Only keys this package stored: anything else in the store stays.
        const id = blobJobId(key);
        if (!id) {
          continue;
        }
        if (!ended.has(id)) {
          const job = await adapter.get(id);
          ended.set(id, !job || isTerminal(job) || job.state === "expired");
        }
        if (ended.get(id)) {
          await adapter.deleteBlob(key);
        }
      }
    },
  };
}
