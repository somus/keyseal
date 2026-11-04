import type {
  CertificateFacts,
  DigestAlgorithm,
  KeyUsage,
  RsaPadding,
  SignatureAlgorithm,
} from "./types.js";

export interface InspectedCertificate {
  subject: string;
  subjectCommonName: string | null;
  issuer: string;
  /** The issuer name's CN; null when it has none or several. */
  issuerCommonName: string | null;
  /** The subject name's O; null when it has none or several. */
  subjectOrganization: string | null;
  /** Dotted-decimal OIDs in the certificatePolicies extension; empty without it. */
  policyOids: string[];
  /** Uppercase hex. */
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  /**
   * The digitalSignature and nonRepudiation bits its KeyUsage extension
   * asserts; null without the extension.
   */
  keyUsage: KeyUsage[] | null;
  /** Whether its basicConstraints extension marks it a CA. */
  ca: boolean;
  /** Null when the key is not RSA or a supported curve, or cannot be read. */
  key: CertificateFacts["key"] | null;
}

/**
 * X.509 parsing, kept behind an interface so a runtime without `node:crypto`
 * can supply its own.
 */
export interface CertificateInspector {
  /** Null when `der` is not an X.509 certificate. */
  inspect(der: Uint8Array): InspectedCertificate | null;
  /**
   * Whether `signature` is the certificate's key signing `data` with
   * `algorithm` and `digest` (protocol section 11.1): RSA-PSS with MGF1 over
   * the digest and a salt of the digest's length, ECDSA as a DER
   * ECDSA-Sig-Value. False for anything that can't be checked.
   */
  verify(
    der: Uint8Array,
    data: Uint8Array,
    signature: Uint8Array,
    algorithm: SignatureAlgorithm,
    digest: DigestAlgorithm
  ): boolean;
}

/** Protocol section 11.1: the digest each supported key signs with. */
export function digestFor(key: CertificateFacts["key"]): DigestAlgorithm {
  return key.type === "ec" &&
    (key.curve === "P-384" || key.curve === "brainpoolP384r1")
    ? "sha384"
    : "sha256";
}

/** The scheme `key` signs with when RSA keys use `rsaPadding`. */
export function schemeFor(
  key: CertificateFacts["key"],
  rsaPadding: RsaPadding
): SignatureAlgorithm {
  if (key.type === "ec") {
    return "ecdsa";
  }
  return rsaPadding === "pss" ? "rsa-pss" : "rsa-pkcs1-v1_5";
}
