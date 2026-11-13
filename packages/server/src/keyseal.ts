import { type CertificateInspector } from "./certificates.js";
import { randomToken, sha256Hex } from "./encoding.js";
import { createHandlers, type Action } from "./handlers.js";
import {
  checkDocuments,
  checkPolicy,
  checkText,
  SHA256_HEX,
} from "./job-input.js";
import { nodeCertificateInspector } from "./node-certificates.js";
import { checkOptions } from "./options.js";
import { error } from "./requests.js";
import { type SigningService } from "./service.js";
import {
  createTransitions,
  isExpired,
  isTerminal,
  pdfKey,
} from "./transitions.js";
import type {
  Adapter,
  CertificatePolicy,
  DigestAlgorithm,
  Job,
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

const EXPIRED_MESSAGE = "The signing link expired. Start again.";

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
  service: SigningService;
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
  const { adapter, service } = options;
  const inspector = options.certificateInspector ?? nodeCertificateInspector;
  const clock = options.now ?? (() => new Date());
  const basePath = options.basePath ?? "";
  const minVersion = checkOptions(options, basePath);
  const { branding } = options;

  const jobsPath = `${basePath}/v1/jobs`;
  const route = new RegExp(
    `^${escapeRegExp(jobsPath)}/([^/]+)(?:/(certificate|signature|failure)|/documents/(0|[1-9][0-9]*))?$`
  );

  function jobUrl(token: string): string {
    return `${options.origin}${jobsPath}/${token}`;
  }

  const transitions = createTransitions(adapter, clock);
  const { deleteBlobs } = transitions;
  const handleJob = createHandlers({
    adapter,
    clock,
    inspector,
    jobUrl,
    minVersion,
    options,
    service,
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
    await expire();
    const now = clock();
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
    // The job first: a sweep deletes the blobs of a job it can't find, and
    // nobody has the token yet to use the job before its PDFs are stored.
    await adapter.create(job);
    for (const [index, entry] of (sign?.documents ?? []).entries()) {
      await adapter.putBlob(pdfKey(id, index), entry.pdf);
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

    async sweep() {
      await expire();
      // A deletion that failed, or a request that stopped, after its job
      // ended leaves blobs that nothing else deletes. Open jobs keep theirs.
      const ended = new Map<string, boolean>();
      for (const key of await adapter.listBlobs()) {
        // Only keys this package stored: anything else in the store stays.
        const id = key.slice(0, 64);
        if (!SHA256_HEX.test(id) || key[64] !== "/") {
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
