import { digestFor, type CertificateInspector } from "./certificates.js";
import { fromBase64, sha256Hex } from "./encoding.js";
import type { SigningService } from "./service.js";
import type { CertificateFacts, CertificatePolicy, Job } from "./types.js";

/**
 * Protocol section 8.2. The issuer CN comes from the certificate's issuer
 * name; the chain check to a trusted root (section 8.3) binds that name to
 * the CA that signed it. Without `keyUsage`, nonRepudiation is required.
 */
function satisfies(
  facts: Pick<
    CertificateFacts,
    | "policyOids"
    | "issuerCommonName"
    | "subjectOrganization"
    | "keyUsage"
    | "ca"
  >,
  policy: CertificatePolicy
): boolean {
  const usage = facts.keyUsage ?? [];
  return (
    !facts.ca &&
    (usage.includes("nonRepudiation") ||
      (policy.keyUsage === "digitalSignature" &&
        usage.includes("digitalSignature"))) &&
    (policy.policyOids === undefined ||
      policy.policyOids.some((oid) => facts.policyOids.includes(oid))) &&
    (policy.issuerCommonNames === undefined ||
      (facts.issuerCommonName !== null &&
        policy.issuerCommonNames.includes(facts.issuerCommonName))) &&
    (policy.subjectOrganization === undefined ||
      facts.subjectOrganization === policy.subjectOrganization)
  );
}

export async function inspect(
  inspector: CertificateInspector,
  der: string,
  chain: string[]
): Promise<Omit<CertificateFacts, "revocationChecked"> | string> {
  const bytes = fromBase64(der);
  const inspected = inspector.inspect(bytes);
  if (!inspected) {
    return "The certificate could not be read.";
  }
  if (!inspected.key) {
    return "The certificate's key is not supported. Use an RSA, P-256, P-384 or brainpool certificate.";
  }
  return {
    ...inspected,
    chain,
    der,
    key: inspected.key,
    sha256: await sha256Hex(bytes),
  };
}

/** Protocol section 8.3: the checks before the service prepares a signature. */
export async function acceptCertificate(
  inspector: CertificateInspector,
  service: SigningService,
  job: Job,
  der: string,
  chain: string[],
  now: Date
): Promise<CertificateFacts | string> {
  const facts = await inspect(inspector, der, chain);
  if (typeof facts === "string") {
    return facts;
  }
  if (now < facts.notBefore || now >= facts.notAfter) {
    return "The certificate is not valid now.";
  }
  if (
    job.expectedCertificateSha256 &&
    facts.sha256 !== job.expectedCertificateSha256
  ) {
    return "This is not the certificate this job expects. Use the one registered for you.";
  }
  if (job.certificatePolicy && !satisfies(facts, job.certificatePolicy)) {
    return "This certificate is not one this job accepts. Use a certificate of the kind the job asks for.";
  }
  if (job.digestAlgorithm && digestFor(facts.key) !== job.digestAlgorithm) {
    return "The certificate's key does not match the digest this job announced.";
  }
  return await trustCertificate(service, job, facts);
}

/**
 * The signing service's chain, key usage and revocation check, as both
 * rounds ask it.
 */
export async function trustCertificate(
  service: SigningService,
  job: Job,
  facts: Omit<CertificateFacts, "revocationChecked">
): Promise<CertificateFacts | string> {
  const { trusted, revocationChecked } = await service.certificate({
    certificate: facts.der,
    chain: facts.chain,
    keyUsage: job.certificatePolicy?.keyUsage ?? "nonRepudiation",
  });
  if (!trusted) {
    return "The certificate is not from a trusted certifying authority, or may not sign.";
  }
  return { ...facts, revocationChecked };
}
