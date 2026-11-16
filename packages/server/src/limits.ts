/** Protocol section 9.2: a job expires this long after creation, whatever its state. */
export const JOB_TTL_MS = 15 * 60 * 1000;
/** Protocol section 9.3: a settle lease older than this may be taken over. */
export const SETTLE_LEASE_MS = 5 * 60 * 1000;
/** Protocol section 8.1. */
export const MAX_BODY_BYTES = 262_144;
/** Protocol section 8.2: a sign job's documents. */
export const MAX_DOCUMENTS = 20;
/** The service refuses larger PDFs. */
export const MAX_PDF_BYTES = 25 * 1024 * 1024;
/**
 * The PDFs of one sign job together. Protocol section 8.4 caps the prepared
 * documents at 256 MiB; this leaves room for what preparing adds to each.
 */
export const MAX_JOB_PDF_BYTES = 240 * 1024 * 1024;
