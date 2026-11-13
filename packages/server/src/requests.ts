import { isBase64, readBody } from "./encoding.js";
import { characters, isObject } from "./job-input.js";
import { MAX_BODY_BYTES } from "./keyseal.js";
import type { JobState } from "./types.js";

export const TOKEN = /^[A-Za-z0-9_-]{20,128}$/;
const MAX_CERTIFICATE_LENGTH = 16_384;
const MAX_CHAIN = 8;
const MAX_SIGNATURE_LENGTH = 4096;

export function json(body: object, status = 200): Response {
  return Response.json(body, {
    headers: { "Cache-Control": "no-store" },
    status,
  });
}

export function error(status: number, message: string): Response {
  return json({ message }, status);
}

function isSignature(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_SIGNATURE_LENGTH &&
    isBase64(value)
  );
}

function isCertificate(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_CERTIFICATE_LENGTH &&
    isBase64(value)
  );
}

type Submission =
  | {
      action: "certificate";
      claimNonce: string;
      certificate: string;
      chain: string[];
    }
  | { action: "signature"; claimNonce: string; signatures: string[] }
  | { action: "failure"; claimNonce: string; message: string };

/** Protocol section 9.2: the states each POST needs. */
export const NEEDS: Record<Submission["action"], JobState[]> = {
  certificate: ["claimed"],
  failure: ["claimed", "prepared"],
  signature: ["prepared"],
};

/** Reads a POST body as JSON: the parsed value, or the 413 or 422 response. */
export async function readJson(request: Request): Promise<unknown> {
  if (Number(request.headers.get("Content-Length") ?? "0") > MAX_BODY_BYTES) {
    return error(413, "The request is too large.");
  }
  const bytes = await readBody(request.body, MAX_BODY_BYTES);
  if (!bytes) {
    return error(413, "The request is too large.");
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return error(422, "The request is not valid JSON.");
  }
}

/**
 * Reads and checks a POST body: the submission, or the 413 or 422 response.
 * A signature submission must carry one signature per document.
 */
export async function readSubmission(
  request: Request,
  action: Submission["action"],
  documents: number
): Promise<Submission | Response> {
  const body = await readJson(request);
  if (body instanceof Response) {
    return body;
  }
  if (
    !isObject(body) ||
    typeof body.claimNonce !== "string" ||
    !TOKEN.test(body.claimNonce)
  ) {
    return error(422, "The request has no valid claimNonce.");
  }
  const { claimNonce } = body;
  if (action === "certificate") {
    const { certificate, chain } = body;
    if (
      isCertificate(certificate) &&
      Array.isArray(chain) &&
      chain.length <= MAX_CHAIN &&
      chain.every(isCertificate)
    ) {
      return { action, certificate, chain, claimNonce };
    }
    return error(
      422,
      "The request needs a certificate and a chain of base64 DER certificates."
    );
  }
  if (action === "signature") {
    const { signatures } = body;
    if (
      Array.isArray(signatures) &&
      signatures.length === documents &&
      signatures.every(isSignature)
    ) {
      return { action, claimNonce, signatures };
    }
    return error(
      422,
      "The request needs one base64 signature per document, in order."
    );
  }
  const message = typeof body.message === "string" ? body.message.trim() : "";
  const length = characters(message);
  if (length >= 1 && length <= 500) {
    return { action, claimNonce, message };
  }
  return error(422, "The request needs a message of 1 to 500 characters.");
}
