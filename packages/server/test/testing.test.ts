import { expect, test } from "bun:test";

import { createMemoryAdapter, type Adapter } from "../src/index.js";
import {
  adapterConformanceChecks,
  AdapterConformanceError,
  runAdapterConformance,
} from "../src/testing.js";

const memory = () => createMemoryAdapter({ onCompleted: async () => {} });

for (const check of adapterConformanceChecks(memory)) {
  test(`memory adapter: ${check.name}`, check.run);
}

test("an adapter that drops milliseconds fails the precision check", async () => {
  const truncating = (): Adapter => {
    const adapter = memory();
    return {
      ...adapter,
      async transition(id, expected, patch) {
        const lease = patch.leaseStartedAt;
        return await adapter.transition(
          id,
          expected,
          lease
            ? {
                ...patch,
                leaseStartedAt: new Date(
                  Math.floor(lease.getTime() / 1000) * 1000
                ),
              }
            : patch
        );
      },
    };
  };
  const error = await runAdapterConformance(truncating).catch(
    (cause: unknown) => cause
  );
  expect(error).toBeInstanceOf(AdapterConformanceError);
  expect((error as AdapterConformanceError).check).toBe(
    "leaseStartedAt keeps millisecond precision"
  );
});

test("an expiry that ignores the lease cutoff fails", async () => {
  const careless = (): Adapter => {
    const adapter = memory();
    return {
      ...adapter,
      expireOlderThan: (cutoff) =>
        adapter.expireOlderThan(cutoff, new Date(8.64e15)),
    };
  };
  const failures: string[] = [];
  for (const check of adapterConformanceChecks(careless)) {
    await check
      .run()
      .catch((cause: AdapterConformanceError) => failures.push(cause.check));
  }
  expect(failures).toEqual([
    "expireOlderThan expires exactly the open, unleased jobs created before the cutoff",
  ]);
});

test("an expiry that reads, then writes, fails the atomicity check", async () => {
  const racy = (): Adapter => {
    const adapter = memory();
    return {
      ...adapter,
      async expireOlderThan(cutoff, leaseCutoff) {
        const open = [...adapter.jobs.values()].filter(
          (job) =>
            ["pending", "claimed", "prepared"].includes(job.state) &&
            job.createdAt < cutoff &&
            !(job.leaseStartedAt && job.leaseStartedAt >= leaseCutoff)
        );
        await Promise.resolve();
        for (const job of open) {
          const current = adapter.jobs.get(job.id);
          await adapter.transition(
            job.id,
            {
              leaseStartedAt: current?.leaseStartedAt ?? null,
              state: job.state,
            },
            { state: "expired" }
          );
        }
        return open;
      },
    };
  };
  const failures: string[] = [];
  for (const check of adapterConformanceChecks(racy)) {
    await check
      .run()
      .catch((cause: AdapterConformanceError) => failures.push(cause.check));
  }
  expect(failures).toEqual([
    "expireOlderThan is atomic against concurrent expiry and lease takeover",
  ]);
});
