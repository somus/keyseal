import {
  InvalidJobInput,
  MAX_DOCUMENTS,
  MAX_JOB_PDF_BYTES,
} from "./keyseal.js";
import { MAX_PDF_BYTES } from "./service.js";
import type {
  CertificatePolicy,
  JobDocument,
  SignatureDetails,
} from "./types.js";

export const SHA256_HEX = /^[0-9a-f]{64}$/;
const FIELD_NAME = /^[A-Za-z0-9_]{1,64}$/;
// Protocol section 8.2: dotted-decimal OIDs, and the certificate policy's limits.
const OID = /^[0-2](?:\.(?:0|[1-9][0-9]*))+$/;
const MAX_OID_LENGTH = 128;
const MAX_POLICY_ENTRIES = 16;

/** Protocol section 1: lengths in characters count Unicode code points. */
export function characters(value: string): number {
  return [...value].length;
}

export function checkText(name: string, value: unknown, max: number): void {
  const length = typeof value === "string" ? characters(value) : 0;
  if (length < 1 || length > max) {
    throw new InvalidJobInput(`${name} must be 1 to ${max} characters`);
  }
}

function checkList(
  name: string,
  value: unknown,
  check: (item: unknown) => boolean,
  each: string
): void {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > MAX_POLICY_ENTRIES ||
    !value.every(check)
  ) {
    throw new InvalidJobInput(
      `${name} must be a list of 1 to ${MAX_POLICY_ENTRIES} entries, each ${each}`
    );
  }
}

/** Protocol section 8.2: a copy of the policy with only its known members. */
export function checkPolicy(policy: unknown): CertificatePolicy {
  if (!isObject(policy)) {
    throw new InvalidJobInput("certificatePolicy must be an object");
  }
  const { policyOids, issuerCommonNames, subjectOrganization, keyUsage } =
    policy;
  const checked: CertificatePolicy = {};
  if (policyOids !== undefined) {
    checkList(
      "certificatePolicy.policyOids",
      policyOids,
      (oid) =>
        typeof oid === "string" &&
        oid.length <= MAX_OID_LENGTH &&
        OID.test(oid),
      `a dotted-decimal OID of at most ${MAX_OID_LENGTH} characters`
    );
    checked.policyOids = [...(policyOids as string[])];
  }
  if (issuerCommonNames !== undefined) {
    checkList(
      "certificatePolicy.issuerCommonNames",
      issuerCommonNames,
      (name) =>
        typeof name === "string" &&
        characters(name) >= 1 &&
        characters(name) <= 200,
      "1 to 200 characters"
    );
    checked.issuerCommonNames = [...(issuerCommonNames as string[])];
  }
  if (subjectOrganization !== undefined) {
    checkText(
      "certificatePolicy.subjectOrganization",
      subjectOrganization,
      200
    );
    checked.subjectOrganization = subjectOrganization as string;
  }
  if (keyUsage !== undefined) {
    if (keyUsage !== "nonRepudiation" && keyUsage !== "digitalSignature") {
      throw new InvalidJobInput(
        'certificatePolicy.keyUsage must be "nonRepudiation" or "digitalSignature"'
      );
    }
    checked.keyUsage = keyUsage;
  }
  if (Object.keys(checked).length === 0) {
    throw new InvalidJobInput(
      "certificatePolicy needs policyOids, issuerCommonNames, subjectOrganization or keyUsage"
    );
  }
  return checked;
}

const CONTROL = /\p{Cc}/u;

/** The given members trimmed, or null when none are. */
function checkSignatureDetails(
  value: unknown,
  name: string
): SignatureDetails | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InvalidJobInput(`${name} must be an object`);
  }
  const given = value as Record<string, unknown>;
  const details: SignatureDetails = {};
  for (const member of ["reason", "location", "contactInfo"] as const) {
    const text = given[member];
    if (text === undefined) {
      continue;
    }
    const trimmed = typeof text === "string" ? text.trim() : "";
    checkText(`${name}.${member}`, trimmed, 200);
    if (CONTROL.test(trimmed)) {
      throw new InvalidJobInput(
        `${name}.${member} must not contain control characters`
      );
    }
    details[member] = trimmed;
  }
  return Object.keys(details).length > 0 ? details : null;
}

/** A sign job's documents as the job stores them; their PDFs become blobs. */
export function checkDocuments(
  value: unknown,
  jobTitle: string
): JobDocument[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > MAX_DOCUMENTS
  ) {
    throw new InvalidJobInput(
      `documents must be a list of 1 to ${MAX_DOCUMENTS} documents`
    );
  }
  let total = 0;
  const documents = value.map((entry: unknown, index): JobDocument => {
    const name = `documents[${index}]`;
    if (!isObject(entry)) {
      throw new InvalidJobInput(`${name} must be an object`);
    }
    const { fieldName, pdf, signatureDetails, stampStyle } = entry;
    if (typeof fieldName !== "string" || !FIELD_NAME.test(fieldName)) {
      throw new InvalidJobInput(
        `${name}.fieldName must be 1 to 64 letters, digits or underscores`
      );
    }
    if (!(pdf instanceof Uint8Array)) {
      throw new InvalidJobInput(`${name}.pdf must be a Uint8Array`);
    }
    if (pdf.byteLength > MAX_PDF_BYTES) {
      throw new InvalidJobInput(`${name}.pdf must be at most 25 MiB`);
    }
    total += pdf.byteLength;
    if (stampStyle !== undefined) {
      checkText(`${name}.stampStyle`, stampStyle, 64);
    }
    const title = entry.title ?? (value.length === 1 ? jobTitle : undefined);
    if (title === undefined) {
      throw new InvalidJobInput(
        `${name}.title is required when a job has several documents`
      );
    }
    checkText(`${name}.title`, title, 200);
    return {
      fieldName,
      signatureDetails:
        signatureDetails === undefined
          ? null
          : checkSignatureDetails(signatureDetails, `${name}.signatureDetails`),
      stampStyle: (stampStyle as string | undefined) ?? null,
      title: title as string,
      toSign: null,
    };
  });
  if (total > MAX_JOB_PDF_BYTES) {
    throw new InvalidJobInput(
      "documents must hold at most 240 MiB of PDF together"
    );
  }
  return documents;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
