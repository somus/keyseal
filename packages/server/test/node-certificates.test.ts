import { describe, expect, test } from "bun:test";

import { nodeCertificateInspector } from "../src/index.js";
import {
  BRAINPOOL_SIGNATURES,
  CERTS,
  signWith,
  toSignFor,
} from "./support.js";

describe("node certificate inspector", () => {
  test("refuses DER with another certificate appended as PEM", () => {
    const rsa = Buffer.from(CERTS.rsa, "base64");
    const pem = `\n-----BEGIN CERTIFICATE-----\n${CERTS.p256}\n-----END CERTIFICATE-----\n`;
    const blob = Buffer.concat([rsa, Buffer.from(pem)]);
    expect(nodeCertificateInspector.inspect(rsa)?.subjectCommonName).toBe(
      "Test Signer rsa"
    );
    expect(nodeCertificateInspector.inspect(blob)).toBeNull();
    const data = Buffer.from("signed attributes");
    const signature = signWith("rsa", data.toString("base64"));
    expect(
      nodeCertificateInspector.verify(
        blob,
        data,
        Buffer.from(signature, "base64"),
        "rsa-pkcs1-v1_5",
        "sha256"
      )
    ).toBe(false);
  });

  test("verifies each scheme with the certificate's key and refuses the rest", () => {
    const data = Buffer.from("signed attributes");
    const der = (name: keyof typeof CERTS) =>
      Buffer.from(CERTS[name], "base64");
    const verify = (
      name: keyof typeof CERTS,
      signature: string,
      algorithm: "rsa-pkcs1-v1_5" | "rsa-pss" | "ecdsa",
      digest: "sha256" | "sha384"
    ) =>
      nodeCertificateInspector.verify(
        der(name),
        data,
        Buffer.from(signature, "base64"),
        algorithm,
        digest
      );
    const toSign = data.toString("base64");
    const pkcs1 = signWith("rsa", toSign);
    const pss = signWith("rsa", toSign, "rsa-pss");
    const p256 = signWith("p256", toSign);
    const p384 = signWith("p384", toSign);
    expect(verify("rsa", pkcs1, "rsa-pkcs1-v1_5", "sha256")).toBe(true);
    expect(verify("rsa", pss, "rsa-pss", "sha256")).toBe(true);
    expect(verify("p256", p256, "ecdsa", "sha256")).toBe(true);
    expect(verify("p384", p384, "ecdsa", "sha384")).toBe(true);

    expect(verify("rsa", pkcs1, "rsa-pss", "sha256")).toBe(false);
    expect(verify("rsa", pss, "rsa-pkcs1-v1_5", "sha256")).toBe(false);
    expect(verify("rsa", pkcs1, "ecdsa", "sha256")).toBe(false);
    expect(verify("p256", p256, "rsa-pkcs1-v1_5", "sha256")).toBe(false);
    expect(verify("p256", p256, "ecdsa", "sha384")).toBe(false);
    expect(verify("p384", p256, "ecdsa", "sha384")).toBe(false);
    expect(verify("rsa", btoa("garbage"), "rsa-pkcs1-v1_5", "sha256")).toBe(
      false
    );
    expect(
      nodeCertificateInspector.verify(
        new Uint8Array([1, 2, 3]),
        data,
        Buffer.from(pkcs1, "base64"),
        "rsa-pkcs1-v1_5",
        "sha256"
      )
    ).toBe(false);
  });
});

describe("node certificate inspector, brainpool and key usage", () => {
  const der = (name: keyof typeof CERTS) => Buffer.from(CERTS[name], "base64");

  test("reads brainpool keys and verifies their signatures", () => {
    const data = Buffer.from(toSignFor("Signature1"), "base64");
    const verify = (
      name: keyof typeof CERTS,
      signature: Uint8Array,
      algorithm: "rsa-pkcs1-v1_5" | "ecdsa",
      digest: "sha256" | "sha384",
      signed: Uint8Array = data
    ) =>
      nodeCertificateInspector.verify(
        der(name),
        signed,
        signature,
        algorithm,
        digest
      );
    const p256 = Buffer.from(BRAINPOOL_SIGNATURES.brainpoolP256r1, "base64");
    const p384 = Buffer.from(BRAINPOOL_SIGNATURES.brainpoolP384r1, "base64");
    expect(
      nodeCertificateInspector.inspect(der("brainpoolP256r1"))?.key
    ).toEqual({ curve: "brainpoolP256r1", type: "ec" });
    expect(
      nodeCertificateInspector.inspect(der("brainpoolP384r1"))?.key
    ).toEqual({ curve: "brainpoolP384r1", type: "ec" });
    expect(verify("brainpoolP256r1", p256, "ecdsa", "sha256")).toBe(true);
    expect(verify("brainpoolP384r1", p384, "ecdsa", "sha384")).toBe(true);

    const tampered = Buffer.from(p256);
    tampered[tampered.length - 1]! ^= 1;
    expect(verify("brainpoolP256r1", tampered, "ecdsa", "sha256")).toBe(false);
    expect(
      verify("brainpoolP256r1", p256, "ecdsa", "sha256", Buffer.from("other"))
    ).toBe(false);
    expect(verify("brainpoolP256r1", p256, "ecdsa", "sha384")).toBe(false);
    expect(verify("brainpoolP256r1", p256, "rsa-pkcs1-v1_5", "sha256")).toBe(
      false
    );
    expect(verify("brainpoolP384r1", p256, "ecdsa", "sha384")).toBe(false);
    expect(verify("p256", p256, "ecdsa", "sha256")).toBe(false);
    expect(
      verify("brainpoolP256r1", Buffer.from([0x30, 0]), "ecdsa", "sha256")
    ).toBe(false);
  });

  test("reads the KeyUsage bits and whether it is a CA", () => {
    const inspect = (name: keyof typeof CERTS) => {
      const inspected = nodeCertificateInspector.inspect(der(name));
      return { ca: inspected?.ca, keyUsage: inspected?.keyUsage };
    };
    expect(inspect("usage-signature")).toEqual({
      ca: false,
      keyUsage: ["digitalSignature"],
    });
    expect(inspect("usage-nonrepudiation")).toEqual({
      ca: false,
      keyUsage: ["nonRepudiation"],
    });
    expect(inspect("policy")).toEqual({
      ca: false,
      keyUsage: ["digitalSignature", "nonRepudiation"],
    });
    expect(inspect("usage-none")).toEqual({ ca: false, keyUsage: null });
    expect(inspect("usage-ca")).toEqual({
      ca: true,
      keyUsage: ["nonRepudiation"],
    });
  });
});
