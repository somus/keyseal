import { constants, createHash, verify, X509Certificate } from "node:crypto";

import { type BrainpoolCurve, verifyBrainpool } from "./brainpool.js";
import type {
  CertificateInspector,
  InspectedCertificate,
} from "./certificates.js";
import type { EcCurve, KeyUsage } from "./types.js";

const EC_PUBLIC_KEY = "1.2.840.10045.2.1";

/** Protocol section 11.1: the supported curves by their OIDs. */
const CURVES = new Map<string, EcCurve>([
  ["1.2.840.10045.3.1.7", "P-256"],
  ["1.3.132.0.34", "P-384"],
  ["1.3.36.3.3.2.8.1.1.7", "brainpoolP256r1"],
  ["1.3.36.3.3.2.8.1.1.11", "brainpoolP384r1"],
]);

function commonName(distinguishedName: string): string | null {
  const part = distinguishedName
    .split("\n")
    .find((line) => line.startsWith("CN="));
  return part ? part.slice(3) : null;
}

/** The value of a name's only attribute of a type; null for none or several. */
function only(value: string | string[] | undefined): string | null {
  return typeof value === "string" ? value : null;
}

interface Element {
  tag: number;
  start: number;
  end: number;
}

/** The DER element at `offset`: its tag and where its contents lie. */
function element(der: Uint8Array, offset: number): Element {
  let start = offset + 2;
  let length = der[offset + 1] ?? 0;
  if (length >= 0x80) {
    const count = length - 0x80;
    length = 0;
    for (const byte of der.subarray(start, start + count)) {
      length = length * 256 + byte;
    }
    start += count;
  }
  if (offset + 2 > der.length || start + length > der.length) {
    throw new RangeError("Truncated DER");
  }
  return { end: start + length, start, tag: der[offset]! };
}

/** The elements inside a constructed element. */
function children(der: Uint8Array, parent: Element): Element[] {
  const found: Element[] = [];
  for (let offset = parent.start; offset < parent.end;) {
    const child = element(der, offset);
    found.push(child);
    offset = child.end;
  }
  return found;
}

/** An OBJECT IDENTIFIER's contents in dotted-decimal form. */
function oid(bytes: Uint8Array): string {
  const arcs: bigint[] = [];
  let arc = 0n;
  for (const byte of bytes) {
    arc = (arc << 7n) | BigInt(byte & 0x7f);
    if (byte < 0x80) {
      arcs.push(arc);
      arc = 0n;
    }
  }
  const first = arcs.shift() ?? 0n;
  const top = first < 80n ? first / 40n : 2n;
  return [top, first - top * 40n, ...arcs].join(".");
}

function oidAt(der: Uint8Array, at: Element): string {
  return oid(der.subarray(at.start, at.end));
}

/** The TBSCertificate's elements. */
function tbsElements(der: Uint8Array): Element[] {
  const [tbs] = children(der, element(der, 0));
  return children(der, tbs!);
}

/**
 * The value of the extension with `id`, which `X509Certificate` does not
 * expose: TBSCertificate, its `[3]` extensions, and the extension's
 * extnValue OCTET STRING, whose contents are the value's DER.
 */
function extensionValue(der: Uint8Array, id: string): Element | null {
  const extensions = tbsElements(der).find((child) => child.tag === 0xa3);
  if (!extensions) {
    return null;
  }
  for (const extension of children(der, children(der, extensions)[0]!)) {
    const [extnId, ...rest] = children(der, extension);
    if (oidAt(der, extnId!) === id) {
      return element(der, rest.at(-1)!.start);
    }
  }
  return null;
}

const CERTIFICATE_POLICIES = "2.5.29.32";
const KEY_USAGE = "2.5.29.15";

/** The policy identifiers in the certificatePolicies extension. */
function policyOids(der: Uint8Array): string[] {
  const policies = extensionValue(der, CERTIFICATE_POLICIES);
  if (!policies) {
    return [];
  }
  return children(der, policies).map((policy) =>
    oidAt(der, children(der, policy)[0]!)
  );
}

/**
 * The digitalSignature (bit 0) and nonRepudiation (bit 1) bits the KeyUsage
 * BIT STRING asserts (RFC 5280 section 4.2.1.3); its first content byte
 * counts the unused bits.
 */
function keyUsage(der: Uint8Array): KeyUsage[] | null {
  const bits = extensionValue(der, KEY_USAGE);
  if (!bits) {
    return null;
  }
  const first = bits.end - bits.start > 1 ? der[bits.start + 1]! : 0;
  const asserted: KeyUsage[] = [];
  if (first & 0x80) {
    asserted.push("digitalSignature");
  }
  if (first & 0x40) {
    asserted.push("nonRepudiation");
  }
  return asserted;
}

/**
 * The SubjectPublicKeyInfo's algorithm, its parameters OID if any, and the
 * public key's BIT STRING contents without the unused-bits byte. Read from
 * the DER, since Bun's `node:crypto` cannot decode brainpool keys.
 */
function publicKeyInfo(der: Uint8Array): {
  algorithm: string;
  parameters: string | null;
  key: Uint8Array;
} {
  const tbs = tbsElements(der);
  // version [0], serial, signature, issuer, validity, subject, then the key.
  const info = tbs[tbs[0]!.tag === 0xa0 ? 6 : 5]!;
  const [algorithm, key] = children(der, info);
  const [id, parameters] = children(der, algorithm!);
  return {
    algorithm: oidAt(der, id!),
    key: der.subarray(key!.start + 1, key!.end),
    parameters: parameters?.tag === 0x06 ? oidAt(der, parameters) : null,
  };
}

function readKey(
  certificate: X509Certificate,
  der: Uint8Array
): InspectedCertificate["key"] {
  try {
    const { algorithm, parameters } = publicKeyInfo(der);
    if (algorithm === EC_PUBLIC_KEY) {
      const curve = CURVES.get(parameters ?? "");
      return curve ? { curve, type: "ec" } : null;
    }
    const key = certificate.publicKey;
    if (key.asymmetricKeyType === "rsa") {
      return {
        bits: key.asymmetricKeyDetails?.modulusLength ?? 0,
        type: "rsa",
      };
    }
    return null;
  } catch {
    return null;
  }
}

/** Whether `signature`, a DER ECDSA-Sig-Value, is the brainpool key's over `data`. */
function verifyBrainpoolSignature(
  der: Uint8Array,
  curve: BrainpoolCurve,
  data: Uint8Array,
  signature: Uint8Array,
  digest: string
): boolean {
  const sequence = element(signature, 0);
  const integers = children(signature, sequence);
  if (
    sequence.tag !== 0x30 ||
    sequence.end !== signature.length ||
    integers.length !== 2 ||
    integers.some((integer) => integer.tag !== 0x02)
  ) {
    return false;
  }
  const [r, s] = integers.map((integer) =>
    signature.subarray(integer.start, integer.end)
  );
  return verifyBrainpool(
    curve,
    publicKeyInfo(der).key,
    createHash(digest).update(data).digest(),
    r!,
    s!
  );
}

/**
 * The certificate `der` holds, only if it is exactly one DER certificate.
 * `X509Certificate` also reads PEM, skipping any bytes before the BEGIN line,
 * so DER with a PEM certificate appended would parse as the appended one while
 * the policy walk and the signing service read the leading DER.
 */
function parse(der: Uint8Array): X509Certificate {
  const certificate = new X509Certificate(der);
  if (!certificate.raw.equals(der)) {
    throw new TypeError("Not a single DER certificate");
  }
  return certificate;
}

/** The default inspector, on `node:crypto` (Node, Bun, Workers with nodejs_compat). */
export const nodeCertificateInspector: CertificateInspector = {
  inspect(der) {
    let certificate: X509Certificate;
    let policies: string[];
    let usage: KeyUsage[] | null;
    try {
      certificate = parse(der);
      policies = policyOids(der);
      usage = keyUsage(der);
    } catch {
      return null;
    }
    // Unlike `subject` and `issuer`, the legacy object's values are not escaped.
    const { issuer, subject } = certificate.toLegacyObject();
    return {
      ca: certificate.ca,
      issuer: certificate.issuer.replaceAll("\n", ", "),
      issuerCommonName: only(issuer.CN),
      key: readKey(certificate, der),
      keyUsage: usage,
      notAfter: new Date(certificate.validTo),
      notBefore: new Date(certificate.validFrom),
      policyOids: policies,
      serialNumber: certificate.serialNumber.toUpperCase(),
      subject: certificate.subject.replaceAll("\n", ", "),
      subjectCommonName: commonName(certificate.subject),
      subjectOrganization: only(subject.O),
    };
  },
  verify(der, data, signature, algorithm, digest) {
    try {
      const certificate = parse(der);
      const read = readKey(certificate, der);
      if (
        read?.type === "ec" &&
        (read.curve === "brainpoolP256r1" || read.curve === "brainpoolP384r1")
      ) {
        return (
          algorithm === "ecdsa" &&
          verifyBrainpoolSignature(der, read.curve, data, signature, digest)
        );
      }
      const key = certificate.publicKey;
      const isEc = key.asymmetricKeyType === "ec";
      if (isEc !== (algorithm === "ecdsa")) {
        return false;
      }
      if (algorithm === "ecdsa") {
        return verify(digest, data, { dsaEncoding: "der", key }, signature);
      }
      if (algorithm === "rsa-pss") {
        return verify(
          digest,
          data,
          {
            key,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: digest === "sha384" ? 48 : 32,
          },
          signature
        );
      }
      return verify(
        digest,
        data,
        { key, padding: constants.RSA_PKCS1_PADDING },
        signature
      );
    } catch {
      return false;
    }
  },
};
