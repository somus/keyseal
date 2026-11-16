import { SHA256_HEX } from "./job-input.js";
import type { Adapter } from "./types.js";

// The blob key layout. Integrators' stores hold these keys and `sweep`
// parses them, so they must not change: each document's PDF until round 1,
// then the signing service's state for each document until the job ends.

export function pdfKey(id: string, index: number): string {
  return `${id}/pdf/${index}`;
}

/** Keyed by lease, so a request whose lease was taken over cannot replace the winner's states. */
export function stateKey(id: string, lease: Date): string {
  return `${id}/state/${lease.getTime()}`;
}

export function stateBlobKey(stateKey: string, index: number): string {
  return `${stateKey}/${index}`;
}

/** The id of the job a key belongs to; null for a key this package didn't store. */
export function blobJobId(key: string): string | null {
  const id = key.slice(0, 64);
  return SHA256_HEX.test(id) && key[64] === "/" ? id : null;
}

/** A job's PDFs, one per document. */
export async function deletePdfs(
  adapter: Adapter,
  id: string,
  count: number
): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    await adapter.deleteBlob(pdfKey(id, index));
  }
}
