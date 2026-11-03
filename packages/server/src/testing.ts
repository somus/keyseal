import { randomUUID } from "node:crypto";
import { inspect, isDeepStrictEqual } from "node:util";

import type { Adapter, Job, JobPatch } from "./types.js";

/** One check of the adapter contract, runnable under any test framework. */
export interface AdapterConformanceCheck {
  name: string;
  run: () => Promise<void>;
}

/** Thrown by a failed check; `check` names it. */
export class AdapterConformanceError extends Error {
  constructor(
    readonly check: string,
    message: string
  ) {
    super(`${check}: ${message}`);
    this.name = "AdapterConformanceError";
  }
}

// The checks date their jobs in 2001 and look only at the jobs they created,
// so an expiry check never touches a live job, but they leave their jobs and
// blobs behind.
const BASE = Date.UTC(2001, 0, 1);
const at = (ms: number) => new Date(BASE + ms);

function makeJob(overrides: Partial<Job> = {}): Job {
  return {
    certificate: null,
    certificatePolicy: {
      issuerCommonNames: ["Example CA 2026"],
      policyOids: ["2.16.356.100.2.3"],
      subjectOrganization: "Example Trust",
    },
    chain: null,
    claimNonceHash: null,
    createdAt: at(0),
    digestAlgorithm: "sha384",
    documents: [
      {
        fieldName: "Signature1",
        signatureDetails: {
          contactInfo: "a@example.org",
          location: "Mumbai",
          reason: "Approved",
        },
        stampStyle: null,
        title: "Board resolution 2026/14",
        toSign: null,
      },
      {
        fieldName: "Signature2",
        signatureDetails: null,
        stampStyle: "plain",
        title: "Minutes",
        toSign: null,
      },
    ],
    error: null,
    expectedCertificateSha256: "ab".repeat(32),
    id: randomUUID().replaceAll("-", "").repeat(2),
    kind: "sign",
    leaseStartedAt: null,
    reference: "conformance",
    rsaPadding: "pss",
    signer: "Asha Rao",
    state: "pending",
    stateKey: null,
    title: "Board pack, 2 documents",
    ...overrides,
  };
}

/**
 * The invariants `createKeySeal` relies on from an adapter, one check each.
 * `makeAdapter` is called once per check; point it at a disposable store,
 * since the checks write to it. Register each check with your test runner, or call
 * `runAdapterConformance` to run them in turn.
 */
export function adapterConformanceChecks(
  makeAdapter: () => Adapter | Promise<Adapter>
): AdapterConformanceCheck[] {
  const checks: [
    string,
    (adapter: Adapter, fail: (message: string) => never) => Promise<void>,
  ][] = [
    [
      "get returns a created job unchanged, with Date fields as Dates",
      async (adapter, fail) => {
        for (const job of [
          makeJob(),
          makeJob({
            certificatePolicy: null,
            digestAlgorithm: null,
            documents: [],
            kind: "enrol",
            reference: null,
          }),
        ]) {
          await adapter.create(job);
          const stored = await adapter.get(job.id);
          if (!(stored?.createdAt instanceof Date)) {
            fail(
              `createdAt came back as ${inspect(stored?.createdAt)}; it must be a Date`
            );
          }
          if (!isDeepStrictEqual(stored, job)) {
            fail(
              `stored ${inspect(job, { depth: 4 })}, got ${inspect(stored, { depth: 4 })}`
            );
          }
        }
      },
    ],
    [
      "get returns null for an unknown id",
      async (adapter, fail) => {
        const stored = await adapter.get(makeJob().id);
        if (stored !== null) {
          fail(`got ${inspect(stored)}`);
        }
      },
    ],
    [
      "leaseStartedAt keeps millisecond precision",
      async (adapter, fail) => {
        const job = makeJob();
        await adapter.create(job);
        const lease = at(1_234);
        if (
          !(await adapter.transition(
            job.id,
            { leaseStartedAt: null, state: "pending" },
            { leaseStartedAt: lease }
          ))
        ) {
          fail("taking the lease of a pending job returned false");
        }
        const stored = await adapter.get(job.id);
        if (
          !(stored?.leaseStartedAt instanceof Date) ||
          stored.leaseStartedAt.getTime() !== lease.getTime()
        ) {
          fail(
            `stored ${lease.toISOString()}, got ${inspect(stored?.leaseStartedAt)}; a column without milliseconds, such as MySQL DATETIME instead of DATETIME(3), makes every settle fail`
          );
        }
        // The server settles with the Date it took the lease with, not one it read back.
        if (
          !(await adapter.transition(
            job.id,
            { leaseStartedAt: new Date(lease.getTime()), state: "pending" },
            { leaseStartedAt: null }
          ))
        ) {
          fail(
            "releasing the lease with the Date it was taken with returned false"
          );
        }
      },
    ],
    [
      "transition applies the patch only while state and leaseStartedAt match",
      async (adapter, fail) => {
        const job = makeJob();
        await adapter.create(job);
        const lease = at(5_001);
        const refused: [
          string,
          { state: Job["state"]; leaseStartedAt: Date | null },
        ][] = [
          ["another state", { leaseStartedAt: null, state: "claimed" }],
          [
            "a lease on a job without one",
            { leaseStartedAt: lease, state: "pending" },
          ],
        ];
        for (const [what, expected] of refused) {
          if (await adapter.transition(job.id, expected, { state: "failed" })) {
            fail(`transition expecting ${what} returned true`);
          }
        }
        if (
          await adapter.transition(
            makeJob().id,
            { leaseStartedAt: null, state: "pending" },
            { state: "failed" }
          )
        ) {
          fail("transition of an unknown id returned true");
        }
        const claim: JobPatch = {
          claimNonceHash: "cd".repeat(32),
          leaseStartedAt: lease,
          state: "claimed",
        };
        if (
          !(await adapter.transition(
            job.id,
            { leaseStartedAt: null, state: "pending" },
            claim
          ))
        ) {
          fail("transition with a matching state and lease returned false");
        }
        let current: Job = { ...job, ...claim };
        if (!isDeepStrictEqual(await adapter.get(job.id), current)) {
          fail(
            `after a claim, expected ${inspect(current, { depth: 4 })}, got ${inspect(await adapter.get(job.id), { depth: 4 })}`
          );
        }
        for (const [what, other] of [
          ["no lease", null],
          ["a lease 1 ms later", at(5_002)],
        ] as const) {
          if (
            await adapter.transition(
              job.id,
              { leaseStartedAt: other, state: "claimed" },
              { state: "failed" }
            )
          ) {
            fail(`transition expecting ${what} on a leased job returned true`);
          }
        }
        const prepared: JobPatch = {
          certificate: "MIIB",
          chain: ["MIIC", "MIID"],
          documents: job.documents.map((document, index) => ({
            ...document,
            toSign: `MYI${index}`,
          })),
          leaseStartedAt: null,
          state: "prepared",
          stateKey: "state-key",
        };
        if (
          !(await adapter.transition(
            job.id,
            { leaseStartedAt: new Date(lease.getTime()), state: "claimed" },
            prepared
          ))
        ) {
          fail(
            "transition expecting an equal lease in another Date instance returned false"
          );
        }
        current = { ...current, ...prepared };
        if (!isDeepStrictEqual(await adapter.get(job.id), current)) {
          fail(
            `after round 1, expected ${inspect(current, { depth: 4 })}, got ${inspect(await adapter.get(job.id), { depth: 4 })}`
          );
        }
      },
    ],
    [
      "concurrent transitions from the same expected state: exactly one wins",
      async (adapter, fail) => {
        const job = makeJob();
        await adapter.create(job);
        const leases = Array.from({ length: 8 }, (_, index) =>
          at(10_000 + index)
        );
        const results = await Promise.all(
          leases.map((lease) =>
            adapter.transition(
              job.id,
              { leaseStartedAt: null, state: "pending" },
              { leaseStartedAt: lease }
            )
          )
        );
        const won = results.filter(Boolean).length;
        if (won !== 1) {
          fail(`${won} of ${leases.length} transitions returned true`);
        }
        const winner = leases[results.indexOf(true)];
        const stored = await adapter.get(job.id);
        if (stored?.leaseStartedAt?.getTime() !== winner?.getTime()) {
          fail(
            `the stored lease ${inspect(stored?.leaseStartedAt)} is not the winner's ${inspect(winner)}`
          );
        }
      },
    ],
    [
      "expireOlderThan expires exactly the open, unleased jobs created before the cutoff",
      async (adapter, fail) => {
        const cutoff = at(60_000);
        const leaseCutoff = at(50_000);
        const cases: [string, Partial<Job>, boolean][] = [
          ["pending", {}, true],
          ["claimed", { state: "claimed" }, true],
          [
            "prepared with a stale lease",
            { leaseStartedAt: at(49_999), state: "prepared" },
            true,
          ],
          [
            "prepared with a live lease",
            { leaseStartedAt: at(55_000), state: "prepared" },
            false,
          ],
          [
            "claimed with a lease at the lease cutoff",
            { leaseStartedAt: leaseCutoff, state: "claimed" },
            false,
          ],
          ["pending, created at the cutoff", { createdAt: cutoff }, false],
          [
            "pending, created after the cutoff",
            { createdAt: at(60_001) },
            false,
          ],
          ["completed", { state: "completed" }, false],
          ["failed", { error: "Refused.", state: "failed" }, false],
          ["expired", { state: "expired" }, false],
        ];
        const jobs = cases.map(([, overrides]) =>
          makeJob({ stateKey: "state-key", ...overrides })
        );
        for (const job of jobs) {
          await adapter.create(job);
        }
        const returned = await adapter.expireOlderThan(cutoff, leaseCutoff);
        for (const [index, [what, , expires]] of cases.entries()) {
          const job = jobs[index] as Job;
          const entry = returned.filter((candidate) => candidate.id === job.id);
          if (entry.length !== (expires ? 1 : 0)) {
            fail(
              `a ${what} job was returned ${entry.length} times; expected ${expires ? 1 : 0}`
            );
          }
          // The server deletes the returned jobs' blobs, which these name.
          if (
            entry[0] &&
            (!isDeepStrictEqual(entry[0].documents, job.documents) ||
              entry[0].stateKey !== job.stateKey)
          ) {
            fail(
              `the returned ${what} job lost its documents or stateKey: ${inspect(entry[0], { depth: 4 })}`
            );
          }
          const state = (await adapter.get(job.id))?.state;
          const want = expires ? "expired" : job.state;
          if (state !== want) {
            fail(`a ${what} job is ${state} after expiry; expected ${want}`);
          }
        }
        const again = await adapter.expireOlderThan(cutoff, leaseCutoff);
        if (
          again.some((candidate) => jobs.some((job) => job.id === candidate.id))
        ) {
          fail("a second expireOlderThan returned a job the first one expired");
        }
      },
    ],
    [
      "expireOlderThan is atomic against concurrent expiry and lease takeover",
      async (adapter, fail) => {
        const cutoff = at(60_000);
        const leaseCutoff = at(50_000);
        const jobs = Array.from({ length: 8 }, () =>
          makeJob({ state: "claimed" })
        );
        for (const job of jobs) {
          await adapter.create(job);
        }
        const [first, second, ...taken] = await Promise.all([
          adapter.expireOlderThan(cutoff, leaseCutoff),
          adapter.expireOlderThan(cutoff, leaseCutoff),
          ...jobs.map((job) =>
            adapter.transition(
              job.id,
              { leaseStartedAt: null, state: "claimed" },
              { leaseStartedAt: at(55_000) }
            )
          ),
        ]);
        for (const [index, job] of jobs.entries()) {
          const count = [...first, ...second].filter(
            (candidate) => candidate.id === job.id
          ).length;
          const state = (await adapter.get(job.id))?.state;
          if (count > 1) {
            fail(`job ${index} was returned by both concurrent expiries`);
          }
          if (taken[index] && count > 0) {
            fail(`job ${index} took a live lease and was also expired`);
          }
          if (state !== (count === 1 ? "expired" : "claimed")) {
            fail(
              `job ${index} is ${state} after being returned ${count} times`
            );
          }
          if (!taken[index] && count === 0) {
            fail(`job ${index} was neither leased nor expired`);
          }
        }
      },
    ],
    [
      "blobs round-trip bytes, overwrite and delete",
      async (adapter, fail) => {
        const key = `${makeJob().id}/pdf/0`;
        const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
        if ((await adapter.getBlob(key)) !== null) {
          fail("getBlob of a missing key did not return null");
        }
        await adapter.putBlob(key, bytes);
        const stored = await adapter.getBlob(key);
        if (
          !(stored instanceof Uint8Array) ||
          !isDeepStrictEqual(Uint8Array.from(stored), bytes)
        ) {
          fail(`getBlob returned ${inspect(stored)} for 256 bytes 0 to 255`);
        }
        const replaced = Uint8Array.of(1, 2, 3);
        await adapter.putBlob(key, replaced);
        const overwritten = await adapter.getBlob(key);
        if (
          !overwritten ||
          !isDeepStrictEqual(Uint8Array.from(overwritten), replaced)
        ) {
          fail(`putBlob did not overwrite: got ${inspect(overwritten)}`);
        }
        await adapter.deleteBlob(key);
        if ((await adapter.getBlob(key)) !== null) {
          fail("getBlob after deleteBlob did not return null");
        }
        await adapter.deleteBlob(key);
      },
    ],
  ];
  return checks.map(([name, check]) => ({
    name,
    run: async () => {
      await check(await makeAdapter(), (message) => {
        throw new AdapterConformanceError(name, message);
      });
    },
  }));
}

/** Runs every check in turn and throws the first failure. */
export async function runAdapterConformance(
  makeAdapter: () => Adapter | Promise<Adapter>
): Promise<void> {
  for (const check of adapterConformanceChecks(makeAdapter)) {
    await check.run();
  }
}
