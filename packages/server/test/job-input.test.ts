import { describe, expect, test } from "bun:test";

import { InvalidJobInput, type SignDocumentInput } from "../src/index.js";
import { BATCH, PDF, setup, type JobOptions } from "./support.js";

describe("job input", () => {
  test("validates the documents when a job is created", async () => {
    const t = setup();
    const invalid: [JobOptions, string][] = [
      [{ documents: [] }, "documents must be a list of 1 to 20 documents"],
      [
        {
          documents: Array.from({ length: 21 }, (_, n) => ({
            ...BATCH[0]!,
            title: `${n}`,
          })),
        },
        "documents must be a list of 1 to 20 documents",
      ],
      [
        { documents: "x" as unknown as SignDocumentInput[] },
        "documents must be a list",
      ],
      [
        { documents: [BATCH[0]!, { fieldName: "Signature2", pdf: PDF }] },
        "documents[1].title is required when a job has several documents",
      ],
      [
        { documents: [BATCH[0]!, { ...BATCH[1]!, title: "" }] },
        "documents[1].title must be 1 to 200 characters",
      ],
      [
        { documents: [BATCH[0]!, { ...BATCH[1]!, fieldName: "a b" }] },
        "documents[1].fieldName must be",
      ],
      [
        { documents: [null as unknown as SignDocumentInput] },
        "documents[0] must be an object",
      ],
      [
        {
          documents: [{ ...BATCH[0]!, signatureDetails: { reason: "\u0007" } }],
        },
        "documents[0].signatureDetails.reason must not contain control characters",
      ],
    ];
    for (const [input, message] of invalid) {
      const attempt = t.signJob(input);
      await expect(attempt).rejects.toThrow(TypeError);
      await expect(attempt).rejects.toThrow(message);
    }
    // 25 MiB each is allowed, but not more than 240 MiB together.
    const large = new Uint8Array(24 * 1024 * 1024);
    const many = Array.from({ length: 11 }, (_, n) => ({
      fieldName: `Signature${n}`,
      pdf: large,
      title: `Document ${n}`,
    }));
    await expect(t.signJob({ documents: many })).rejects.toThrow(
      "documents must hold at most 240 MiB of PDF together"
    );
    expect(t.adapter.jobs.size).toBe(0);
    expect(t.adapter.blobs.size).toBe(0);

    // One document takes the job's title unless it has its own.
    const single = await t.signJob({ title: "Lease" });
    expect((await t.jobFor(single.token)).documents[0]?.title).toBe("Lease");
    const own = await t.signJob({
      documents: [{ ...BATCH[0]!, title: "lease.pdf" }],
      title: "Lease",
    });
    expect((await t.claim(own.token)).documents).toEqual([
      { document: expect.any(String), title: "lease.pdf" },
    ]);
    const twenty = await t.signJob({
      documents: Array.from({ length: 20 }, (_, n) => ({
        ...BATCH[0]!,
        title: `Document ${n}`,
      })),
    });
    expect((await t.jobFor(twenty.token)).documents).toHaveLength(20);
  });

  test("validates the policy when a job is created", async () => {
    const t = setup();
    const invalid: unknown[] = [
      "2.16.356.100.2.3",
      {},
      { unknown: ["x"] },
      { policyOids: [] },
      { policyOids: "2.16.356.100.2.3" },
      { policyOids: ["2.16.356.100.2.03"] },
      { policyOids: ["3.1"] },
      { policyOids: ["2"] },
      { policyOids: ["2.16..356"] },
      { policyOids: [" 2.16.356"] },
      { policyOids: [`2.${"1".repeat(127)}`] },
      { policyOids: Array.from({ length: 17 }, (_, i) => `2.${i}`) },
      { issuerCommonNames: [""] },
      { issuerCommonNames: ["x".repeat(201)] },
      { issuerCommonNames: [1] },
      { subjectOrganization: "" },
      { keyUsage: "keyCertSign" },
      { keyUsage: "NonRepudiation" },
      { keyUsage: ["nonRepudiation"] },
      { keyUsage: null },
      { policyOids: ["2.16.356.100.2.3"], keyUsage: "" },
    ];
    for (const certificatePolicy of invalid) {
      const input = {
        certificatePolicy,
        signer: "Asha Rao",
        title: "DSC enrolment",
      } as Parameters<typeof t.keyseal.createEnrolJob>[0];
      await expect(t.keyseal.createEnrolJob(input)).rejects.toThrow(TypeError);
      await expect(t.signJob(input)).rejects.toThrow(TypeError);
    }
    const { token } = await t.keyseal.createEnrolJob({
      certificatePolicy: {
        policyOids: [`2.${"1".repeat(126)}`, "0.0"],
        subjectOrganization: "é".repeat(200),
        unknown: true,
      } as never,
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    expect((await t.jobFor(token)).certificatePolicy).toEqual({
      policyOids: [`2.${"1".repeat(126)}`, "0.0"],
      subjectOrganization: "é".repeat(200),
    });
  });

  test("counts lengths in code points", async () => {
    const t = setup();
    const { id, token } = await t.signJob({
      signer: "\u{1F58B}".repeat(200),
      title: "\u{1F4DD}".repeat(200),
    });
    await expect(t.signJob({ title: "\u{1F4DD}".repeat(201) })).rejects.toThrow(
      TypeError
    );
    const { claimNonce } = await t.claim(token);
    const message = "\u{1F6AB}".repeat(500);
    expect(
      (await t.post(token, "failure", { claimNonce, message })).status
    ).toBe(200);
    expect(await t.keyseal.status(id)).toMatchObject({
      message,
      state: "failed",
    });
  });

  test("invalid job input has its own error, unlike options or an adapter's TypeError", async () => {
    const t = setup();
    await expect(t.signJob({ title: "" })).rejects.toThrow(InvalidJobInput);
    await expect(
      t.keyseal.createEnrolJob({ reference: "r", signer: "", title: "T" })
    ).rejects.toThrow(InvalidJobInput);
    try {
      setup({ branding: { name: "" } });
      throw new Error("an empty branding name was accepted");
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect(error).not.toBeInstanceOf(InvalidJobInput);
    }
    t.adapter.create = async () => {
      throw new TypeError("fetch failed");
    };
    const outage = await t.signJob().catch((error: unknown) => error);
    expect(outage).toBeInstanceOf(TypeError);
    expect(outage).not.toBeInstanceOf(InvalidJobInput);
  });

  test("validates sign job input at runtime", async () => {
    const t = setup();
    const invalid: [Record<string, unknown>, string][] = [
      [
        { digestAlgorithm: "SHA256" },
        "digestAlgorithm must be sha256 or sha384",
      ],
      [{ rsaPadding: "PSS" }, "rsaPadding must be pkcs1 or pss"],
      [
        { expectedCertificateSha256: "a".repeat(63) },
        "expectedCertificateSha256",
      ],
      [
        { expectedCertificateSha256: "g".repeat(64) },
        "expectedCertificateSha256",
      ],
      [{ expectedCertificateSha256: 42 }, "expectedCertificateSha256"],
      [{ title: "" }, "title must be 1 to 200 characters"],
      [{ title: "x".repeat(201) }, "title must be 1 to 200 characters"],
      [{ title: 42 }, "title must be 1 to 200 characters"],
      [{ signer: "" }, "signer must be 1 to 200 characters"],
      [{ signer: "x".repeat(201) }, "signer must be 1 to 200 characters"],
      [{ signer: undefined }, "signer must be 1 to 200 characters"],
      [{ fieldName: 7 }, "fieldName must be"],
      [{ pdf: "%PDF" }, "pdf must be a Uint8Array"],
      [{ pdf: new ArrayBuffer(4) }, "pdf must be a Uint8Array"],
      [
        { pdf: new Uint8Array(25 * 1024 * 1024 + 1) },
        "pdf must be at most 25 MiB",
      ],
      [{ stampStyle: "" }, "stampStyle must be 1 to 64 characters"],
      [{ stampStyle: 1 }, "stampStyle must be 1 to 64 characters"],
      [{ signatureDetails: "Approved" }, "signatureDetails must be an object"],
      [{ signatureDetails: null }, "signatureDetails must be an object"],
      [
        { signatureDetails: { reason: "  " } },
        "signatureDetails.reason must be 1 to 200 characters",
      ],
      [
        { signatureDetails: { location: "x".repeat(201) } },
        "signatureDetails.location must be 1 to 200 characters",
      ],
      [
        { signatureDetails: { contactInfo: 42 } },
        "signatureDetails.contactInfo must be 1 to 200 characters",
      ],
      [
        { signatureDetails: { reason: "Approved\nby me" } },
        "signatureDetails.reason must not contain control characters",
      ],
      [
        { signatureDetails: { location: "Mumbai\u0085" } },
        "signatureDetails.location must not contain control characters",
      ],
    ];
    for (const [input, message] of invalid) {
      const attempt = t.signJob(input as JobOptions);
      await expect(attempt).rejects.toThrow(TypeError);
      await expect(attempt).rejects.toThrow(message);
    }
    await expect(
      t.keyseal.createEnrolJob({
        signer: "Asha Rao",
        title: "x".repeat(201),
      })
    ).rejects.toThrow("title must be 1 to 200 characters");
    expect(t.adapter.jobs.size).toBe(0);

    const upper = "AB".repeat(32);
    const { token } = await t.signJob({
      digestAlgorithm: "sha384",
      expectedCertificateSha256: upper,
      rsaPadding: "pss",
      title: "\u{1F4DD}".repeat(200),
    });
    const job = await t.jobFor(token);
    expect(job.expectedCertificateSha256).toBe(upper.toLowerCase());
    const enrol = await t.keyseal.createEnrolJob({
      expectedCertificateSha256: upper,
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    expect((await t.jobFor(enrol.token)).expectedCertificateSha256).toBe(
      upper.toLowerCase()
    );
  });
});

describe("options", () => {
  test("rejects invalid options", async () => {
    expect(() => setup({ origin: "https://dash.example.org/" })).toThrow(
      TypeError
    );
    for (const origin of [
      "http://dash.example.org",
      "http://localhost:8787",
      "https://localhost",
      "https://app.localhost",
      "https://192.0.2.1",
      "https://[2001:db8::1]",
      "https://user@dash.example.org",
      "https://dash.example.org?x=1",
      "https://dash.example.org#x",
    ]) {
      expect(() => setup({ origin })).toThrow(TypeError);
    }
    for (const origin of [
      "http://dash.example.org",
      "http://10.0.0.1",
      "https://localhost",
      "https://127.0.0.1",
    ]) {
      expect(() => setup({ allowInsecureOrigin: true, origin })).toThrow(
        TypeError
      );
    }
    for (const origin of ["http://localhost:8787", "http://127.0.0.1:18787"]) {
      expect(() => setup({ allowInsecureOrigin: true, origin })).not.toThrow();
    }
    for (const basePath of [
      "/api/",
      "/api keyseal",
      "/api%20keyseal",
      "/café",
      "/.",
      "/..",
      "/api/../keyseal",
      "/api/./keyseal",
      "/api/..",
    ]) {
      expect(() => setup({ basePath })).toThrow(TypeError);
    }
    expect(() => setup({ basePath: "/api/keyseal_v1.0~x" })).not.toThrow();
    expect(() => setup({ basePath: "/.well/..known/..." })).not.toThrow();
    expect(() => setup({ minHelperVersion: "1.2" })).toThrow(TypeError);
    for (const icon of ["https://other.example/icon.png", "/icon.png", ""]) {
      expect(() => setup({ branding: { icon, name: "X" } })).toThrow(
        "branding.icon must be an absolute URL on the origin"
      );
    }
  });
});
