// Imports the packed @keyseal/server and @keyseal/browser under Node, serves
// the manifest and a job, and runs the adapter conformance suite against the
// memory adapter. scripts/ci/node-smoke.sh installs the tarballs and runs it.
import assert from "node:assert/strict";

import { helperDownloadFor } from "@keyseal/browser";
import {
  createKeySeal,
  createMemoryAdapter,
  ServiceClient,
} from "@keyseal/server";
import { runAdapterConformance } from "@keyseal/server/testing";

const origin = "https://dash.example.org";
const keyseal = createKeySeal({
  adapter: createMemoryAdapter({ onCompleted: async () => {} }),
  branding: { name: "Example Trust" },
  origin,
  // Never called: neither the manifest nor the job description needs it.
  service: new ServiceClient({ token: "unused", url: "http://127.0.0.1:9" }),
});

const manifest = await keyseal.handle(
  new Request(`${origin}/.well-known/keyseal.json`)
);
assert.equal(manifest.status, 200);
assert.equal((await manifest.json()).name, "Example Trust");

const { id, jobUrl } = await keyseal.createEnrolJob({
  signer: "Asha Rao",
  title: "Enrol your signing certificate",
});
const job = await keyseal.handle(
  new Request(jobUrl, { headers: { "X-KeySeal-Version": "1.0.0" } })
);
assert.equal(job.status, 200);
assert.equal((await job.json()).kind, "enrol");
assert.equal((await keyseal.status(id))?.state, "claimed");

await runAdapterConformance(() =>
  createMemoryAdapter({ onCompleted: async () => {} })
);

assert.equal(helperDownloadFor("Mozilla/5.0 (Windows NT 10.0)"), "windows");

console.log(`node ${process.version}: @keyseal/server and @keyseal/browser OK`);
