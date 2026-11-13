import { JOB_TTL_MS, SETTLE_LEASE_MS } from "./keyseal.js";
import { error } from "./requests.js";
import type { Adapter, Job, JobFailure, JobPatch } from "./types.js";

export const NOT_FOUND =
  "This signing link is not valid or has expired. Start again from the page.";
export const BUSY = "This job is busy with another request. Try again shortly.";

export function isTerminal(job: Job): boolean {
  return job.state === "completed" || job.state === "failed";
}

export function isExpired(job: Job, now: Date): boolean {
  if (job.state === "expired") {
    return true;
  }
  return (
    !isTerminal(job) && now.getTime() - job.createdAt.getTime() >= JOB_TTL_MS
  );
}

export function gone(job: Job): Response {
  return error(
    410,
    job.state === "completed"
      ? "This job is already complete."
      : "This job has already ended. Start again from the page."
  );
}

export function pdfKey(id: string, index: number): string {
  return `${id}/pdf/${index}`;
}

/** Protocol section 9.3: a lease younger than 5 minutes cannot be taken over. */
export function leaseHeld(job: Job, now: Date): boolean {
  return (
    job.leaseStartedAt !== null &&
    now.getTime() - job.leaseStartedAt.getTime() <= SETTLE_LEASE_MS
  );
}

export type Transitions = ReturnType<typeof createTransitions>;

/** The job's state changes under the settle lease, and the blobs they free. */
export function createTransitions(adapter: Adapter, clock: () => Date) {
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

  return {
    answerCurrent,
    deleteBlobs,
    deleteStates,
    fail,
    refuse,
    settle,
    withLease,
  };
}
