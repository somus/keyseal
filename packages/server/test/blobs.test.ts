import { expect, test } from "bun:test";

import { blobJobId, pdfKey, stateBlobKey, stateKey } from "../src/blobs.js";

// Integrators' stores already hold keys in this layout, and `sweep` parses
// it: a change here strands their blobs.
const id = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

test("blob keys keep the layout stores already hold", () => {
  expect(pdfKey(id, 0)).toBe(
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0/pdf/0"
  );
  const states = stateKey(id, new Date(Date.UTC(2001, 0, 1)));
  expect(states).toBe(
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0/state/978307200000"
  );
  expect(stateBlobKey(states, 12)).toBe(
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0/state/978307200000/12"
  );
});

test("blobJobId reads the job id only from keys this package stores", () => {
  expect(blobJobId(`${id}/pdf/0`)).toBe(id);
  expect(blobJobId(`${id}/state/978307200000/1`)).toBe(id);
  expect(blobJobId(`${id}/`)).toBe(id);
  expect(blobJobId(id)).toBeNull();
  expect(blobJobId(`${id}x/pdf/0`)).toBeNull();
  expect(blobJobId(`${id.toUpperCase()}/pdf/0`)).toBeNull();
  expect(blobJobId("other/key")).toBeNull();
});
