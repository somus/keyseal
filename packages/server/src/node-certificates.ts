import { constants, verify, X509Certificate } from "node:crypto";

import type {
  CertificateInspector,
  InspectedCertificate,
} from "./certificates.js";

const CURVES = new Map([
  ["prime256v1", "P-256"],
  ["secp384r1", "P-384"],
] as const);

function readKey(certificate: X509Certificate): InspectedCertificate["key"] {
  try {
    // Bun cannot decode some keys, such as secp256k1, and throws here.
    const key = certificate.publicKey;
    if (key.asymmetricKeyType === "rsa") {
      return {
        bits: key.asymmetricKeyDetails?.modulusLength ?? 0,
        type: "rsa",
      };
    }
    if (key.asymmetricKeyType === "ec") {
      const curve = CURVES.get(
        key.asymmetricKeyDetails?.namedCurve as "prime256v1"
      );
      return curve ? { curve, type: "ec" } : null;
    }
    return null;
  } catch {
    return null;
  }
}

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

const CERTIFICATE_POLICIES = "2.5.29.32";

/**
 * The policy identifiers in the certificatePolicies extension, which
 * `X509Certificate` does not expose: Certificate, then TBSCertificate, its
 * `[3]` extensions, and the extension's PolicyInformation sequence.
 */
function policyOids(der: Uint8Array): string[] {
  const [tbs] = children(der, element(der, 0));
  const extensions = children(der, tbs!).find((child) => child.tag === 0xa3);
  if (!extensions) {
    return [];
  }
  for (const extension of children(der, children(der, extensions)[0]!)) {
    const [id, ...rest] = children(der, extension);
    if (oid(der.subarray(id!.start, id!.end)) === CERTIFICATE_POLICIES) {
      const policies = element(der, rest.at(-1)!.start);
      return children(der, policies).map((policy) => {
        const [identifier] = children(der, policy);
        return oid(der.subarray(identifier!.start, identifier!.end));
      });
    }
  }
  return [];
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
    try {
      certificate = parse(der);
      policies = policyOids(der);
    } catch {
      return null;
    }
    // Unlike `subject` and `issuer`, the legacy object's values are not escaped.
    const { issuer, subject } = certificate.toLegacyObject();
    return {
      issuer: certificate.issuer.replaceAll("\n", ", "),
      issuerCommonName: only(issuer.CN),
      key: readKey(certificate),
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
      const key = parse(der).publicKey;
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
