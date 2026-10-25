import type { Adapter, CompletedResult, Job, JobFailure } from "../types.js";

export interface MemoryAdapter extends Adapter {
  readonly jobs: ReadonlyMap<string, Job>;
  readonly blobs: ReadonlyMap<string, Uint8Array>;
}

/**
 * Jobs and blobs in process memory, for tests and the reference server. Every
 * read and write copies, so callers never share a stored job.
 */
export function createMemoryAdapter(options: {
  onCompleted: (job: Job, result: CompletedResult) => Promise<void>;
  onFailed?: (job: Job, failure: JobFailure) => Promise<void>;
}): MemoryAdapter {
  const jobs = new Map<string, Job>();
  const blobs = new Map<string, Uint8Array>();
  return {
    blobs,
    async create(job) {
      if (jobs.has(job.id)) {
        throw new Error(`Job ${job.id} exists`);
      }
      jobs.set(job.id, structuredClone(job));
    },
    async deleteBlob(key) {
      blobs.delete(key);
    },
    async expireOlderThan(cutoff, leaseCutoff) {
      const expired: Job[] = [];
      for (const job of jobs.values()) {
        const open =
          job.state === "pending" ||
          job.state === "claimed" ||
          job.state === "prepared";
        const leased =
          job.leaseStartedAt !== null && job.leaseStartedAt >= leaseCutoff;
        if (open && !leased && job.createdAt < cutoff) {
          expired.push(structuredClone(job));
          job.state = "expired";
        }
      }
      return expired;
    },
    async get(id) {
      const job = jobs.get(id);
      return job ? structuredClone(job) : null;
    },
    async getBlob(key) {
      const bytes = blobs.get(key);
      return bytes ? bytes.slice() : null;
    },
    jobs,
    onCompleted: options.onCompleted,
    ...(options.onFailed ? { onFailed: options.onFailed } : {}),
    async putBlob(key, bytes) {
      blobs.set(key, bytes.slice());
    },
    async transition(id, expected, patch) {
      const job = jobs.get(id);
      if (
        !job ||
        job.state !== expected.state ||
        job.leaseStartedAt?.getTime() !== expected.leaseStartedAt?.getTime()
      ) {
        return false;
      }
      jobs.set(id, { ...job, ...structuredClone(patch) });
      return true;
    },
  };
}
