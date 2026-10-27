export type JobKind = "sign" | "enrol";

export type JobState =
  | "pending"
  | "claimed"
  | "prepared"
  | "completed"
  | "failed"
  | "expired";

export type DigestAlgorithm = "sha256" | "sha384";

export type SignatureAlgorithm = "rsa-pkcs1-v1_5" | "rsa-pss" | "ecdsa";

export type RsaPadding = "pkcs1" | "pss";

/** What PDF viewers show in their signature panel, from the signature dictionary. */
export interface SignatureDetails {
  /** `/Reason`, such as "Approved as Director"; the built-in stamp shows it too. */
  reason?: string;
  /** `/Location`, such as "Mumbai". */
  location?: string;
  /** `/ContactInfo`, such as an email address or phone number. */
  contactInfo?: string;
}

/** One PDF of a sign job, as the adapter stores it; the PDF itself is a blob. */
export interface JobDocument {
  /** Shown to the signer, 1 to 200 characters. */
  title: string;
  /** The empty signature field the service signs in. */
  fieldName: string;
  /** The service's stamp style; null for its default. */
  stampStyle: string | null;
  /** The details written into the signature dictionary, if any. */
  signatureDetails: SignatureDetails | null;
  /** Base64 DER SignedAttributes, set by round 1. */
  toSign: string | null;
}

/**
 * A job as the adapter stores it. The raw token is never stored: `id` is its
 * SHA-256, and the claim nonce is kept the same way.
 */
export interface Job {
  /** Lowercase hex SHA-256 of the job token. */
  id: string;
  kind: JobKind;
  state: JobState;
  title: string;
  signer: string;
  /** The integrator's own reference, handed back with the job. */
  reference: string | null;
  createdAt: Date;
  /** Lowercase hex SHA-256 of the claim nonce, set by the claim. */
  claimNonceHash: string | null;
  /** When the request holding the settle lease acquired it. */
  leaseStartedAt: Date | null;
  expectedCertificateSha256: string | null;
  certificatePolicy: CertificatePolicy | null;
  /** Sign jobs: the digest announced in the job description, if any. */
  digestAlgorithm: DigestAlgorithm | null;
  /** Sign jobs: the documents, 1 to 20 in signing order; empty for enrol. */
  documents: JobDocument[];
  /** Sign jobs: the padding for RSA keys. */
  rsaPadding: RsaPadding;
  /**
   * Set by round 1: the prefix of the signing service's states, one blob per
   * document at `<stateKey>/<index>`.
   */
  stateKey: string | null;
  /** Base64 DER of the certificate accepted in round 1. */
  certificate: string | null;
  /** Base64 DER of the chain posted with it. */
  chain: string[] | null;
  /** The message shown to the page when the job failed. */
  error: string | null;
}

/** The fields `transition` may change. */
export type JobPatch = Partial<Omit<Job, "id" | "kind" | "createdAt">>;

/**
 * Protocol section 8.2: what the certificate must show when the job cannot
 * name one in advance. Every member present must hold; strings compare
 * exactly.
 */
export interface CertificatePolicy {
  /** Dotted-decimal OIDs; the certificatePolicies extension must hold one of them. */
  policyOids?: string[];
  /** The issuing CA's subject CN must equal one of these. */
  issuerCommonNames?: string[];
  /** The certificate subject's O must equal this. */
  subjectOrganization?: string;
}

export interface CertificateFacts {
  /** Base64 DER. */
  der: string;
  /** Base64 DER of the chain the helper posted with it. */
  chain: string[];
  sha256: string;
  subject: string;
  subjectCommonName: string | null;
  issuer: string;
  /** The issuer name's CN; null when it has none or several. */
  issuerCommonName: string | null;
  /** The subject name's O; null when it has none or several. */
  subjectOrganization: string | null;
  /** Dotted-decimal OIDs in the certificatePolicies extension; empty without it. */
  policyOids: string[];
  /** Uppercase hex. */
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  key: { type: "rsa"; bits: number } | { type: "ec"; curve: "P-256" | "P-384" };
  /**
   * Whether the signing service found revocation data that checked out for
   * the certificate and every CA on its path that names a CRL or OCSP
   * responder. False means trusted without a revocation check, as always with
   * the service's default of no fetching.
   */
  revocationChecked: boolean;
}

export type CompletedResult =
  | {
      kind: "sign";
      /** Every signed PDF, in the order of `job.documents`. */
      pdfs: Uint8Array[];
      certificate: CertificateFacts;
    }
  | { kind: "enrol"; certificate: CertificateFacts };

export interface JobFailure {
  /** The message the job failed with, as `status` shows it. */
  message: string;
  /** `helper` for a failure report, `server` for a refusal or an outdated helper. */
  reportedBy: "helper" | "server";
}

/**
 * Storage and the completion callback. `transition` is the only write to an
 * existing job: it applies `patch` only if the job is still in `expected`
 * (state and lease start, compared by time), atomically.
 */
export interface Adapter {
  create(job: Job): Promise<void>;
  get(id: string): Promise<Job | null>;
  transition(
    id: string,
    expected: { state: JobState; leaseStartedAt: Date | null },
    patch: JobPatch
  ): Promise<boolean>;
  /**
   * Moves every pending, claimed or prepared job created before `cutoff` to
   * expired and returns them as they were, so their blobs can be deleted.
   * It must skip a job whose `leaseStartedAt` is at or after `leaseCutoff`:
   * that request holds a live settle lease and may still finish (protocol
   * section 9.2).
   */
  expireOlderThan(cutoff: Date, leaseCutoff: Date): Promise<Job[]>;
  putBlob(key: string, bytes: Uint8Array): Promise<void>;
  getBlob(key: string): Promise<Uint8Array | null>;
  /** Deleting a missing blob is not an error. */
  deleteBlob(key: string): Promise<void>;
  /**
   * Called once every signed PDF or the enrolled certificate is ready, while
   * the request still holds the job, before it is marked completed. A sign
   * job's PDFs arrive together, never some of them. If it throws,
   * the job stays as it was and the helper may retry; a retry that takes over
   * a lapsed lease can call it again for the same job, so keep it idempotent
   * on `job.id`. Throw `JobRefused` to fail the job with its message instead.
   */
  onCompleted(job: Job, result: CompletedResult): Promise<void>;
  /**
   * Called when a job fails, while the request still holds the job, before it
   * is marked failed; not when it expires. Errors are logged and the job fails
   * anyway. Like `onCompleted`, a lease takeover can call it again for the
   * same job.
   */
  onFailed?(job: Job, failure: JobFailure): Promise<void>;
}

export interface JobStatus {
  kind: JobKind;
  state: JobState;
  reference: string | null;
  /** Present when the job failed or expired, written for the user. */
  message?: string;
  expiresAt: Date;
}
