import { describe, expect, spyOn, test } from "bun:test";
import { sign } from "node:crypto";

import { JOB_TTL_MS, type CompletedResult, type Job } from "../src/index.js";
import {
  ANY_PROOF,
  BATCH,
  BRAINPOOL_SIGNATURES,
  CERTS,
  GOOD_SIGNATURE,
  KEYS,
  ORIGIN,
  PDF,
  proofFor,
  setup,
  sha256Hex,
  signWith,
  START,
  toSignFor,
  type Description,
  type JobOptions,
} from "./support.js";

describe("sign flow", () => {
  test("completes both rounds and hands the signed PDF to onCompleted", async () => {
    const t = setup();
    const expected = sha256Hex(CERTS.rsa, "base64");
    const { id, token, link, jobUrl } = await t.signJob({
      digestAlgorithm: "sha256",
      expectedCertificateSha256: expected,
      reference: "resolution-14",
    });
    expect(jobUrl).toBe(`${ORIGIN}/v1/jobs/${token}`);
    expect(link).toBe(`keyseal://sign?job=${encodeURIComponent(jobUrl)}`);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect((await t.keyseal.status(id))?.state).toBe("pending");

    const description = await t.claim(token);
    expect(description).toEqual({
      claimNonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      digestAlgorithm: "sha256",
      documents: [
        {
          document: `${jobUrl}/documents/0`,
          title: "Board resolution 2026/14",
        },
      ],
      expectedCertificateSha256: expected,
      kind: "sign",
      signer: "Asha Rao",
      title: "Board resolution 2026/14",
    });
    expect((await t.keyseal.status(id))?.state).toBe("claimed");

    const round1 = await t.post(token, "certificate", {
      certificate: CERTS.rsa,
      chain: [CERTS.p256],
      claimNonce: description.claimNonce,
    });
    expect(round1.status).toBe(200);
    expect(round1.headers.get("Cache-Control")).toBe("no-store");
    expect(await round1.json()).toEqual({
      digestAlgorithm: "sha256",
      documents: [{ toSign: toSignFor("Signature1") }],
      signatureAlgorithm: "rsa-pkcs1-v1_5",
    });
    expect((await t.keyseal.status(id))?.state).toBe("prepared");
    const start = t.fake.calls.find((call) => call.path === "/sign/start");
    expect(start?.body).toEqual({
      certificate: CERTS.rsa,
      chain: [CERTS.p256],
      fieldName: "Signature1",
      pdf: btoa("%PDF-1.7 test document"),
    });

    const round2 = await t.post(token, "signature", {
      claimNonce: description.claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(round2.status).toBe(200);
    expect(await round2.json()).toEqual({});

    expect(t.completed).toHaveLength(1);
    const [{ job, result }] = t.completed as [
      { job: Job; result: CompletedResult },
    ];
    expect(job.reference).toBe("resolution-14");
    expect(result.kind).toBe("sign");
    if (result.kind === "sign") {
      expect(result.pdfs.map((pdf) => new TextDecoder().decode(pdf))).toEqual([
        "%PDF-1.7 test document prepared signed",
      ]);
    }
    expect(result.certificate).toMatchObject({
      chain: [CERTS.p256],
      der: CERTS.rsa,
      key: { bits: 2048, type: "rsa" },
      notAfter: new Date("2036-01-01T00:00:00Z"),
      notBefore: new Date("2026-01-01T00:00:00Z"),
      revocationChecked: true,
      sha256: expected,
      subjectCommonName: "Test Signer rsa",
    });
    expect(result.certificate.serialNumber).toMatch(/^[0-9A-F]+$/);

    const status = await t.keyseal.status(id);
    expect(status).toEqual({
      expiresAt: new Date(START.getTime() + 15 * 60 * 1000),
      kind: "sign",
      reference: "resolution-14",
      state: "completed",
    });
    expect(t.adapter.blobs.size).toBe(0);
  });

  test("stores only hashes of the token and the claim nonce", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    expect([...t.adapter.jobs.keys()]).toEqual([id]);
    expect(id).toBe(sha256Hex(token));
    const stored = JSON.stringify([...t.adapter.jobs.values()]);
    expect(stored).not.toContain(token);
    expect(stored).not.toContain(claimNonce!);
    expect(t.adapter.jobs.get(id)?.claimNonceHash).toBe(sha256Hex(claimNonce!));
  });

  test("chooses digest and scheme by key", async () => {
    const t = setup();
    const cases = [
      {
        certificate: CERTS.p256,
        expected: { digestAlgorithm: "sha256", signatureAlgorithm: "ecdsa" },
      },
      {
        certificate: CERTS.p384,
        expected: { digestAlgorithm: "sha384", signatureAlgorithm: "ecdsa" },
      },
      {
        certificate: CERTS.brainpoolP256r1,
        expected: { digestAlgorithm: "sha256", signatureAlgorithm: "ecdsa" },
      },
      {
        certificate: CERTS.brainpoolP384r1,
        expected: { digestAlgorithm: "sha384", signatureAlgorithm: "ecdsa" },
      },
      {
        certificate: CERTS.rsa,
        expected: {
          digestAlgorithm: "sha256",
          signatureAlgorithm: "rsa-pkcs1-v1_5",
        },
      },
    ];
    for (const { certificate, expected } of cases) {
      const { prepared } = await t.preparedJob(certificate);
      expect(prepared).toMatchObject(expected);
    }
  });

  test("completes jobs signed with brainpool keys", async () => {
    for (const curve of ["brainpoolP256r1", "brainpoolP384r1"] as const) {
      const t = setup();
      const { id, token, claimNonce, prepared } = await t.preparedJob(
        CERTS[curve]
      );
      expect(prepared.documents[0].toSign).toBe(toSignFor("Signature1"));
      const response = await t.post(token, "signature", {
        claimNonce,
        signatures: [BRAINPOOL_SIGNATURES[curve]],
      });
      expect(response.status).toBe(200);
      expect((await t.keyseal.status(id))?.state).toBe("completed");
      expect(t.completed[0]?.result.certificate.key).toEqual({
        curve,
        type: "ec",
      });
    }
    // A job announcing the other digest refuses the key in round 1.
    const t = setup();
    const { token } = await t.signJob({ digestAlgorithm: "sha256" });
    const { claimNonce } = await t.claim(token);
    const response = await t.post(token, "certificate", {
      certificate: CERTS.brainpoolP384r1,
      chain: [],
      claimNonce,
    });
    expect(response.status).toBe(422);
  });

  test("asks the service for PSS on RSA keys when the job wants it", async () => {
    const t = setup();
    const rsa = await t.preparedJob(CERTS.rsa, {
      rsaPadding: "pss",
      stampStyle: "acme",
    });
    expect(rsa.prepared.signatureAlgorithm).toBe("rsa-pss");
    expect(t.fake.calls.at(-1)?.body).toMatchObject({
      rsaPadding: "pss",
      stampStyle: "acme",
    });

    const ec = await t.preparedJob(CERTS.p256, { rsaPadding: "pss" });
    expect(ec.prepared.signatureAlgorithm).toBe("ecdsa");
    expect(t.fake.calls.at(-1)?.body.rsaPadding).toBeUndefined();
  });

  test("passes the signature details to the service", async () => {
    const t = setup();
    const { token } = await t.preparedJob(CERTS.rsa, {
      signatureDetails: {
        location: " Mumbai ",
        reason: "Approved as Director",
      },
    });
    expect((await t.jobFor(token)).documents[0]?.signatureDetails).toEqual({
      location: "Mumbai",
      reason: "Approved as Director",
    });
    const body = t.fake.calls.at(-1)?.body;
    expect(body).toMatchObject({
      location: "Mumbai",
      reason: "Approved as Director",
    });
    expect(body?.contactInfo).toBeUndefined();

    const plain = await t.preparedJob(CERTS.rsa);
    expect(
      (await t.jobFor(plain.token)).documents[0]?.signatureDetails
    ).toBeNull();
    expect(t.fake.calls.at(-1)?.body.reason).toBeUndefined();
  });

  test("refuses a signature algorithm that does not fit the key or padding", async () => {
    const t = setup();
    for (const [certificate, input, algorithm] of [
      [CERTS.rsa, {}, "ecdsa"],
      [CERTS.rsa, {}, "rsa-pss"],
      [CERTS.rsa, { rsaPadding: "pss" }, "rsa-pkcs1-v1_5"],
      [CERTS.p256, {}, "rsa-pkcs1-v1_5"],
    ] as const) {
      t.fake.signatureAlgorithm = algorithm;
      const { token } = await t.signJob(input);
      const { claimNonce } = await t.claim(token);
      const response = await t.post(token, "certificate", {
        certificate,
        chain: [],
        claimNonce,
      });
      expect(response.status).toBe(500);
      expect((await t.jobFor(token)).state).toBe("claimed");
    }
  });
});

/** Round 2's body for `prepared`, each document signed with `key`. */
function signaturesFor(
  prepared: { documents: { toSign: string }[]; signatureAlgorithm: string },
  key: keyof typeof KEYS = "rsa"
): string[] {
  return prepared.documents.map(({ toSign }) =>
    signWith(key, toSign, prepared.signatureAlgorithm)
  );
}

describe("batch", () => {
  test("signs every document and hands the PDFs over together, in order", async () => {
    const t = setup();
    const { id, token, jobUrl } = await t.signJob({
      documents: [
        { ...BATCH[0]!, stampStyle: "acme" },
        { ...BATCH[1]!, signatureDetails: { reason: "Approved" } },
        BATCH[2]!,
      ],
      title: "Board pack, 3 documents",
    });
    const description = await t.claim(token);
    expect(description).toMatchObject({
      documents: [1, 2, 3].map((n) => ({
        document: `${jobUrl}/documents/${n - 1}`,
        title: `Document ${n}`,
      })),
      title: "Board pack, 3 documents",
    });
    const round1 = await t.post(token, "certificate", {
      certificate: CERTS.p384,
      chain: [],
      claimNonce: description.claimNonce,
    });
    expect(round1.status).toBe(200);
    const prepared = (await round1.json()) as {
      documents: { toSign: string }[];
      signatureAlgorithm: string;
    };
    expect(prepared as unknown).toEqual({
      digestAlgorithm: "sha384",
      documents: [1, 2, 3].map((n) => ({ toSign: toSignFor(`Signature${n}`) })),
      signatureAlgorithm: "ecdsa",
    });
    const starts = t.fake.calls.filter((call) => call.path === "/sign/start");
    expect(starts.map((call) => call.body)).toEqual([
      expect.objectContaining({ fieldName: "Signature1", stampStyle: "acme" }),
      expect.objectContaining({ fieldName: "Signature2", reason: "Approved" }),
      expect.objectContaining({ fieldName: "Signature3" }),
    ]);
    expect(starts[2]?.body.stampStyle).toBeUndefined();

    const headers = {
      Authorization: `Bearer ${token}`,
      "X-KeySeal-Claim": description.claimNonce!,
    };
    for (const n of [1, 2, 3]) {
      const response = await t.send(
        "GET",
        t.jobPath(token, `documents/${n - 1}`),
        { headers }
      );
      expect(await response.text()).toBe(`%PDF-1.7 document ${n} prepared`);
    }

    const round2 = await t.post(token, "signature", {
      claimNonce: description.claimNonce,
      signatures: signaturesFor(prepared, "p384"),
    });
    expect(round2.status).toBe(200);
    expect(t.completed).toHaveLength(1);
    const { result } = t.completed[0]!;
    expect(
      result.kind === "sign" &&
        result.pdfs.map((pdf) => new TextDecoder().decode(pdf))
    ).toEqual([1, 2, 3].map((n) => `%PDF-1.7 document ${n} prepared signed`));
    expect((await t.keyseal.status(id))?.state).toBe("completed");
    expect(t.adapter.blobs.size).toBe(0);
  });

  test("verifies RSA, PSS and ECDSA signatures with the certificate's key", async () => {
    const t = setup();
    for (const [certificate, key, rsaPadding] of [
      [CERTS.rsa, "rsa", "pkcs1"],
      [CERTS.rsa, "rsa", "pss"],
      [CERTS.p256, "p256", "pkcs1"],
      [CERTS.p384, "p384", "pkcs1"],
    ] as const) {
      const { token, claimNonce, prepared } = await t.preparedJob(certificate, {
        documents: BATCH,
        rsaPadding,
        title: "Board pack",
      });
      const response = await t.post(token, "signature", {
        claimNonce,
        signatures: signaturesFor(prepared, key),
      });
      expect(response.status).toBe(200);
    }
    expect(t.completed).toHaveLength(4);
  });

  test("one signature that doesn't verify fails the whole job before any document is finished", async () => {
    const t = setup();
    const { id, token, claimNonce, prepared } = await t.preparedJob(CERTS.rsa, {
      documents: BATCH,
      title: "Board pack",
    });
    const signatures = signaturesFor(prepared);
    // The second document's signature over the first document's attributes.
    signatures[1] = signatures[0]!;
    const response = await t.post(token, "signature", {
      claimNonce,
      signatures,
    });
    expect(response.status).toBe(422);
    expect(await t.keyseal.status(id)).toMatchObject({
      message:
        "The signature doesn't match the certificate: was the right token used?",
      state: "failed",
    });
    expect(t.fake.calls.some((call) => call.path === "/sign/finish")).toBe(
      false
    );
    expect(t.completed).toHaveLength(0);
    expect(t.adapter.blobs.size).toBe(0);

    // Raw r||s from an EC token is refused too.
    const ec = await t.preparedJob(CERTS.p256, {
      documents: BATCH,
      title: "Board pack",
    });
    const der = signaturesFor(ec.prepared, "p256");
    const raw = sign("sha256", Buffer.from(toSignFor("Signature3"), "base64"), {
      dsaEncoding: "ieee-p1363",
      key: KEYS.p256,
    }).toString("base64");
    const refused = await t.post(ec.token, "signature", {
      claimNonce: ec.claimNonce,
      signatures: [der[0], der[1], raw],
    });
    expect(refused.status).toBe(422);
  });

  test("a signature list of another length is 422 and leaves the job prepared", async () => {
    const t = setup();
    const { token, claimNonce, prepared } = await t.preparedJob(CERTS.rsa, {
      documents: BATCH,
      title: "Board pack",
    });
    const signatures = signaturesFor(prepared);
    for (const wrong of [
      signatures.slice(0, 2),
      [...signatures, signatures[0]],
      [],
    ]) {
      const response = await t.post(token, "signature", {
        claimNonce,
        signatures: wrong,
      });
      expect(response.status).toBe(422);
    }
    expect((await t.jobFor(token)).state).toBe("prepared");
    expect(
      (await t.post(token, "signature", { claimNonce, signatures })).status
    ).toBe(200);
  });

  test("a document the service can't finish fails the job and hands over none", async () => {
    const t = setup();
    t.fake.refuseFinish = "Signature2";
    const { id, token, claimNonce, prepared } = await t.preparedJob(CERTS.rsa, {
      documents: BATCH,
      title: "Board pack",
    });
    const response = await t.post(token, "signature", {
      claimNonce,
      signatures: signaturesFor(prepared),
    });
    expect(response.status).toBe(422);
    expect(await t.keyseal.status(id)).toMatchObject({
      message: "The PDF with Signature2 can't be finished",
      state: "failed",
    });
    expect(t.completed).toHaveLength(0);
    expect(t.adapter.blobs.size).toBe(0);
  });

  test("a service failure part way through either round leaves the job for a retry", async () => {
    const t = setup();
    const { token } = await t.signJob({
      documents: BATCH,
      title: "Board pack",
    });
    const { claimNonce } = await t.claim(token);
    const body = { certificate: CERTS.rsa, chain: [], claimNonce };
    t.fake.failStart = "Signature3";
    expect((await t.post(token, "certificate", body)).status).toBe(502);
    // No state of the first two documents is left behind.
    expect([...t.adapter.blobs.keys()].sort()).toEqual(
      [0, 1, 2].map((index) => `${sha256Hex(token)}/pdf/${index}`)
    );
    expect((await t.jobFor(token)).state).toBe("claimed");
    t.fake.failStart = null;
    const round1 = await t.post(token, "certificate", body);
    const prepared = await round1.json();

    t.fake.down = true;
    const signatures = { claimNonce, signatures: signaturesFor(prepared) };
    expect((await t.post(token, "signature", signatures)).status).toBe(502);
    expect((await t.jobFor(token)).state).toBe("prepared");
    expect(t.completed).toHaveLength(0);
    t.fake.down = false;
    expect((await t.post(token, "signature", signatures)).status).toBe(200);
    expect(t.completed).toHaveLength(1);
  });

  test("a lease taken over mid-batch never hands over part of it", async () => {
    const t = setup();
    const { token, claimNonce, prepared } = await t.preparedJob(CERTS.rsa, {
      documents: BATCH,
      title: "Board pack",
    });
    const body = { claimNonce, signatures: signaturesFor(prepared) };
    let open = () => {};
    t.fake.finishGate = new Promise((resolve) => {
      open = resolve;
    });
    // The first request finishes the first document, then waits on the second.
    t.fake.finishGateField = "Signature2";
    const first = t.post(token, "signature", body);
    while (
      t.fake.calls.filter((call) => call.path === "/sign/finish").length < 2
    ) {
      await Bun.sleep(1);
    }
    expect(t.completed).toHaveLength(0);
    t.advance(5 * 60 * 1000 + 1);
    t.fake.finishGateField = "none";
    expect((await t.post(token, "signature", body)).status).toBe(200);
    open();
    expect((await first).status).toBe(410);
    // Both requests may tell the integrator, but only of the whole batch.
    for (const { result } of t.completed) {
      expect(result.kind === "sign" && result.pdfs).toHaveLength(3);
    }
    expect((await t.jobFor(token)).state).toBe("completed");
  });

});

describe("enrol flow", () => {
  test("hands the certificate facts to onCompleted in one round", async () => {
    const t = setup();
    const { id, token, link, jobUrl } = await t.keyseal.createEnrolJob({
      reference: "trustee-7",
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    expect(link).toBe(`keyseal://enrol?job=${encodeURIComponent(jobUrl)}`);
    const description = await t.claim(token);
    expect(Object.keys(description).sort()).toEqual([
      "claimNonce",
      "kind",
      "signer",
      "title",
    ]);
    expect(description.kind).toBe("enrol");

    const response = await t.post(token, "certificate", {
      certificate: CERTS.p384,
      chain: [],
      claimNonce: description.claimNonce,
      proof: proofFor("p384", jobUrl, description.claimNonce, CERTS.p384),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});
    expect(t.completed[0]?.result).toMatchObject({
      certificate: {
        key: { curve: "P-384", type: "ec" },
        revocationChecked: true,
        sha256: sha256Hex(CERTS.p384, "base64"),
      },
      kind: "enrol",
    });
    expect((await t.keyseal.status(id))?.state).toBe("completed");
    expect(t.fake.calls.map((call) => call.path)).toEqual(["/certificate"]);
  });

  test("refuses a certificate other than the expected one", async () => {
    const t = setup();
    const { id, token, jobUrl } = await t.keyseal.createEnrolJob({
      expectedCertificateSha256: sha256Hex(CERTS.rsa, "base64"),
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    const { claimNonce } = await t.claim(token);
    const response = await t.post(token, "certificate", {
      certificate: CERTS.p256,
      chain: [],
      claimNonce,
      proof: proofFor("p256", jobUrl, claimNonce, CERTS.p256),
    });
    expect(response.status).toBe(422);
    expect((await t.keyseal.status(id))?.state).toBe("failed");
  });
});

describe("enrol proof", () => {
  const UPGRADE = "Update the signing helper, then try again.";
  const REFUSED =
    "The proof doesn't match the certificate: was the right token used?";

  test("a valid proof completes the job for RSA, P-256 and P-384 keys", async () => {
    for (const key of ["rsa", "p256", "p384"] as const) {
      const t = setup();
      const { id, token, jobUrl } = await t.keyseal.createEnrolJob({
        signer: "Asha Rao",
        title: "DSC enrolment",
      });
      const { claimNonce } = await t.claim(token);
      const response = await t.post(token, "certificate", {
        certificate: CERTS[key],
        chain: [],
        claimNonce,
        proof: proofFor(key, jobUrl, claimNonce, CERTS[key]),
      });
      expect({ key, status: response.status }).toEqual({ key, status: 200 });
      expect((await t.keyseal.status(id))?.state).toBe("completed");
    }
  });

  test("426 without a proof fails the job and names the first helper that sends one", async () => {
    for (const [minHelperVersion, minVersion] of [
      [undefined, "0.5.0"],
      ["0.4.0", "0.5.0"],
      ["0.5.0", "0.5.0"],
      ["1.2.0", "1.2.0"],
    ] as const) {
      const t = setup(minHelperVersion ? { minHelperVersion } : {});
      const { id, token } = await t.keyseal.createEnrolJob({
        signer: "Asha Rao",
        title: "DSC enrolment",
      });
      const claimed = await t.send("GET", t.jobPath(token), {
        headers: { "X-KeySeal-Version": "9.0.0" },
      });
      const { claimNonce } = (await claimed.json()) as Description;
      const response = await t.send("POST", t.jobPath(token, "certificate"), {
        body: { certificate: CERTS.rsa, chain: [], claimNonce },
        headers: { "X-KeySeal-Version": "9.0.0" },
      });
      expect(response.status).toBe(426);
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect(await response.json()).toEqual({ message: UPGRADE, minVersion });
      expect(await t.keyseal.status(id)).toMatchObject({
        message: UPGRADE,
        state: "failed",
      });
      expect(t.failed.map(({ failure }) => failure)).toEqual([
        { message: UPGRADE, reportedBy: "server" },
      ]);
      expect(t.fake.calls).toEqual([]);
      expect(t.completed).toHaveLength(0);
    }
  });

  test("a sign job's round 1 needs no proof", async () => {
    const { prepared } = await setup().preparedJob();
    expect(prepared).toHaveProperty("documents.0.toSign");
  });

  test("422 for a proof that doesn't verify fails the job", async () => {
    const cases: [
      string,
      (jobUrl: string, claimNonce: string, token: string) => string,
    ][] = [
      ["another key", (url, nonce) => proofFor("p256", url, nonce, CERTS.rsa)],
      [
        "another job URL",
        (_url, nonce) =>
          proofFor(
            "rsa",
            `${ORIGIN}/v1/jobs/${"o".repeat(43)}`,
            nonce,
            CERTS.rsa
          ),
      ],
      [
        "another origin",
        (_url, nonce, token) =>
          proofFor(
            "rsa",
            `https://evil.example/v1/jobs/${token}`,
            nonce,
            CERTS.rsa
          ),
      ],
      [
        "another claim nonce",
        (url) => proofFor("rsa", url, "n".repeat(43), CERTS.rsa),
      ],
      [
        "another certificate",
        (url, nonce) => proofFor("rsa", url, nonce, CERTS.p256),
      ],
      ["a document signature", () => signWith("rsa", toSignFor("Signature1"))],
      ["not a signature", () => btoa("proof")],
    ];
    for (const [name, proof] of cases) {
      const t = setup();
      const { id, token, jobUrl } = await t.keyseal.createEnrolJob({
        signer: "Asha Rao",
        title: "DSC enrolment",
      });
      const { claimNonce } = await t.claim(token);
      const response = await t.post(token, "certificate", {
        certificate: CERTS.rsa,
        chain: [],
        claimNonce,
        proof: proof(jobUrl, claimNonce, token),
      });
      expect({ name, status: response.status }).toEqual({ name, status: 422 });
      expect(await response.json()).toEqual({ message: REFUSED });
      expect(await t.keyseal.status(id)).toMatchObject({
        message: REFUSED,
        state: "failed",
      });
      expect(t.completed).toHaveLength(0);
    }
  });

  test("422 for a proof that isn't base64 leaves the job claimed", async () => {
    for (const proof of ["", "not base64!", 5, null, "A".repeat(4100)]) {
      const t = setup();
      const { id, token } = await t.keyseal.createEnrolJob({
        signer: "Asha Rao",
        title: "DSC enrolment",
      });
      const { claimNonce } = await t.claim(token);
      const response = await t.post(token, "certificate", {
        certificate: CERTS.rsa,
        chain: [],
        claimNonce,
        proof,
      });
      expect(response.status).toBe(422);
      expect((await t.keyseal.status(id))?.state).toBe("claimed");
    }
  });
});

describe("certificate policy", () => {
  const POLICY = {
    issuerCommonNames: ["Other CA", "KeySeal Test Sub CA"],
    policyOids: ["2.16.356.100.2.3"],
    subjectOrganization: "Acme, Inc.",
  };

  test("accepts a policy of only keyUsage, with either value", async () => {
    const t = setup();
    for (const keyUsage of ["nonRepudiation", "digitalSignature"] as const) {
      const { token } = await t.signJob({ certificatePolicy: { keyUsage } });
      expect((await t.jobFor(token)).certificatePolicy).toEqual({ keyUsage });
      expect((await t.claim(token)).certificatePolicy).toEqual({ keyUsage });
    }
  });

  test("requires the key usage the policy asks for", async () => {
    const policies = {
      absent: { subjectOrganization: "Acme, Inc." },
      digitalSignature: { keyUsage: "digitalSignature" },
      nonRepudiation: { keyUsage: "nonRepudiation" },
    } as const;
    const cases: [keyof typeof CERTS, (keyof typeof policies)[]][] = [
      ["usage-signature", ["digitalSignature"]],
      [
        "usage-nonrepudiation",
        ["absent", "digitalSignature", "nonRepudiation"],
      ],
      ["policy", ["absent", "digitalSignature", "nonRepudiation"]],
      ["usage-none", []],
      ["usage-ca", []],
    ];
    for (const [name, accepted] of cases) {
      for (const [setting, certificatePolicy] of Object.entries(policies)) {
        const t = setup({ certificateInspector: ANY_PROOF });
        const { token } = await t.keyseal.createEnrolJob({
          certificatePolicy,
          signer: "Asha Rao",
          title: "DSC enrolment",
        });
        const { claimNonce } = await t.claim(token);
        const response = await t.post(token, "certificate", {
          certificate: CERTS[name],
          chain: [],
          claimNonce,
          proof: "AA==",
        });
        expect({ name, setting, status: response.status }).toEqual({
          name,
          setting,
          status: accepted.includes(setting as keyof typeof policies)
            ? 200
            : 422,
        });
      }
    }
  });

  test("asks the service to check the job's key usage in both rounds", async () => {
    const cases = [
      [undefined, "nonRepudiation"],
      [{ subjectOrganization: "Acme, Inc." }, "nonRepudiation"],
      [{ keyUsage: "nonRepudiation" }, "nonRepudiation"],
      [{ keyUsage: "digitalSignature" }, "digitalSignature"],
    ] as const;
    for (const [certificatePolicy, keyUsage] of cases) {
      const t = setup();
      const certificate =
        certificatePolicy === undefined ? CERTS.rsa : CERTS.policy;
      const { token, claimNonce, prepared } = await t.preparedJob(
        certificate,
        certificatePolicy === undefined ? {} : { certificatePolicy }
      );
      if (certificatePolicy === undefined) {
        await t.post(token, "signature", {
          claimNonce,
          signatures: signaturesFor(prepared),
        });
      }
      const bodies = t.fake.calls
        .filter((call) => call.path === "/certificate")
        .map((call) => call.body);
      expect(bodies.length).toBe(certificatePolicy === undefined ? 2 : 1);
      for (const body of bodies) {
        expect(body).toEqual({ certificate, chain: [], keyUsage });
      }
    }
  });

  test("returns the policy in the job description of both kinds", async () => {
    const t = setup();
    for (const created of [
      await t.keyseal.createEnrolJob({
        certificatePolicy: POLICY,
        signer: "Asha Rao",
        title: "DSC enrolment",
      }),
      await t.signJob({ certificatePolicy: POLICY }),
    ]) {
      const description = await t.claim(created.token);
      expect(description.certificatePolicy as unknown).toEqual(POLICY);
    }
    const description = await t.claim((await t.signJob()).token);
    expect(description).not.toHaveProperty("certificatePolicy");
  });

  test("accepts a certificate that satisfies every member", async () => {
    const t = setup({ certificateInspector: ANY_PROOF });
    const { id, token } = await t.keyseal.createEnrolJob({
      certificatePolicy: POLICY,
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    const { claimNonce } = await t.claim(token);
    const response = await t.post(token, "certificate", {
      certificate: CERTS.policy,
      chain: [],
      claimNonce,
      proof: "AA==",
    });
    expect(response.status).toBe(200);
    expect((await t.keyseal.status(id))?.state).toBe("completed");
    expect(t.completed[0]?.result.certificate).toMatchObject({
      issuerCommonName: "KeySeal Test Sub CA",
      policyOids: ["2.16.356.100.2.2", "2.16.356.100.2.3"],
      subjectOrganization: "Acme, Inc.",
    });
    const { prepared } = await t.preparedJob(CERTS.policy, {
      certificatePolicy: { policyOids: ["1.2.3", "2.16.356.100.2.2"] },
    });
    expect(prepared).toHaveProperty("documents.0.toSign");
  });

  test("refuses with 422 and fails the job when any member does not hold", async () => {
    const cases: [string, Record<string, unknown>][] = [
      [CERTS.policy, { policyOids: ["2.16.356.100.2.1"] }],
      [CERTS.policy, { ...POLICY, issuerCommonNames: ["keyseal test sub ca"] }],
      [CERTS.policy, { ...POLICY, subjectOrganization: "Acme" }],
      [CERTS.policy, { subjectOrganization: "Acme\\, Inc." }],
      [CERTS.rsa, { policyOids: ["2.16.356.100.2.3"] }],
      [CERTS.rsa, { issuerCommonNames: ["KeySeal Test Sub CA"] }],
    ];
    for (const kind of ["enrol", "sign"] as const) {
      for (const [certificate, certificatePolicy] of cases) {
        const t = setup();
        const input = {
          certificatePolicy,
          signer: "Asha Rao",
          title: "DSC enrolment",
        };
        const { id, token } =
          kind === "enrol"
            ? await t.keyseal.createEnrolJob(input)
            : await t.signJob(input);
        const { claimNonce } = await t.claim(token);
        const response = await t.post(token, "certificate", {
          certificate,
          chain: [],
          claimNonce,
          proof: "AA==",
        });
        expect(response.status).toBe(422);
        const message =
          "This certificate is not one this job accepts. Use a certificate of the kind the job asks for.";
        expect(await response.json()).toEqual({ message });
        expect(await t.keyseal.status(id)).toMatchObject({
          message,
          state: "failed",
        });
        expect(t.fake.calls).toEqual([]);
      }
    }
  });
});

describe("status", () => {
  test("looks a job up by its id, not its token", async () => {
    const t = setup();
    const { id, token } = await t.signJob({ reference: "resolution-14" });
    expect(await t.keyseal.status(id)).toEqual({
      expiresAt: new Date(START.getTime() + 15 * 60 * 1000),
      kind: "sign",
      reference: "resolution-14",
      state: "pending",
    });
    expect(await t.keyseal.status(token)).toBeNull();
    expect(await t.keyseal.status(sha256Hex("unknown"))).toBeNull();
    expect(await t.keyseal.status(id.toUpperCase())).toBeNull();
  });
});

describe("status codes", () => {
  test("404 for a malformed, unknown or expired token", async () => {
    const t = setup();
    expect((await t.send("GET", t.jobPath("short"))).status).toBe(404);
    expect((await t.send("GET", t.jobPath("a".repeat(43)))).status).toBe(404);

    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    t.advance(15 * 60 * 1000);
    const response = await t.post(token, "certificate", {
      certificate: CERTS.rsa,
      chain: [],
      claimNonce,
    });
    expect(response.status).toBe(404);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toEqual({ message: expect.any(String) });
    expect(await t.keyseal.status(id)).toMatchObject({
      message: expect.any(String),
      state: "expired",
    });
  });

  test("409 for a second claim, a pending job, a wrong nonce or the wrong state", async () => {
    const t = setup();
    const pending = await t.signJob();
    const early = await t.post(pending.token, "certificate", {
      certificate: CERTS.rsa,
      chain: [],
      claimNonce: "x".repeat(43),
    });
    expect(early.status).toBe(409);

    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    expect((await t.send("GET", t.jobPath(token))).status).toBe(409);
    const wrongNonce = await t.post(token, "certificate", {
      certificate: CERTS.rsa,
      chain: [],
      claimNonce: "y".repeat(43),
    });
    expect(wrongNonce.status).toBe(409);
    const tooEarly = await t.post(token, "signature", {
      claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(tooEarly.status).toBe(409);
    expect((await t.keyseal.status(id))?.state).toBe("claimed");

    const prepared = await t.preparedJob();
    const again = await t.post(prepared.token, "certificate", {
      certificate: CERTS.rsa,
      chain: [],
      claimNonce: prepared.claimNonce,
    });
    expect(again.status).toBe(409);
  });

  test("410 once a job completed or failed", async () => {
    const t = setup();
    const done = await t.preparedJob();
    await t.post(done.token, "signature", {
      claimNonce: done.claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect((await t.send("GET", t.jobPath(done.token))).status).toBe(410);
    const repeat = await t.post(done.token, "signature", {
      claimNonce: done.claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(repeat.status).toBe(410);
    expect(t.completed).toHaveLength(1);

    const failed = await t.preparedJob();
    await t.post(failed.token, "failure", {
      claimNonce: failed.claimNonce,
      message: "Cancelled.",
    });
    const after = await t.post(failed.token, "signature", {
      claimNonce: failed.claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(after.status).toBe(410);
  });

  test("413 for a body over 262144 bytes, by header or by length", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    const large = JSON.stringify({
      certificate: "A".repeat(262_144),
      chain: [],
      claimNonce,
    });
    expect(
      (await t.send("POST", t.jobPath(token, "certificate"), { body: large }))
        .status
    ).toBe(413);

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(large));
        controller.close();
      },
    });
    const response = await t.keyseal.handle(
      new Request(`${ORIGIN}${t.jobPath(token, "certificate")}`, {
        body: stream,
        duplex: "half",
        headers: { "X-KeySeal-Version": "1.0.0" },
        method: "POST",
      } as RequestInit)
    );
    expect(response.status).toBe(413);
    expect((await t.keyseal.status(id))?.state).toBe("claimed");
  });

  test("422 for invalid JSON or schema, leaving the job unchanged", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    const bodies = [
      "{not json",
      "[]",
      { certificate: CERTS.rsa, chain: [] },
      { certificate: CERTS.rsa, claimNonce },
      { certificate: "not base64!", chain: [], claimNonce },
      { certificate: "", chain: [], claimNonce },
      { certificate: CERTS.rsa, chain: [""], claimNonce },
      { certificate: `${CERTS.rsa}A`, chain: [], claimNonce },
      { certificate: "AAAA".repeat(4097), chain: [], claimNonce },
      {
        certificate: CERTS.rsa,
        chain: Array.from({ length: 9 }, () => CERTS.p256),
        claimNonce,
      },
      // Schema comes before the nonce: a malformed body with a wrong nonce is still 422.
      { certificate: 7, chain: [], claimNonce: "z".repeat(43) },
    ];
    for (const body of bodies) {
      const response = await t.send("POST", t.jobPath(token, "certificate"), {
        body,
      });
      expect(response.status).toBe(422);
    }
    expect((await t.keyseal.status(id))?.state).toBe("claimed");

    const signature = await t.post(token, "signature", {
      claimNonce,
      signatures: [""],
    });
    expect(signature.status).toBe(422);
    const failure = await t.post(token, "failure", {
      claimNonce,
      message: "   ",
    });
    expect(failure.status).toBe(422);
    const long = await t.post(token, "failure", {
      claimNonce,
      message: "x".repeat(501),
    });
    expect(long.status).toBe(422);
    expect((await t.keyseal.status(id))?.state).toBe("claimed");
  });

  test("422 for a refused certificate fails the job with the message", async () => {
    const t = setup();
    const refuse = async (certificate: string, input: JobOptions = {}) => {
      const { id, token } = await t.signJob(input);
      const { claimNonce } = await t.claim(token);
      const response = await t.post(token, "certificate", {
        certificate,
        chain: [],
        claimNonce,
      });
      expect(response.status).toBe(422);
      const { message } = (await response.json()) as { message: string };
      expect(await t.keyseal.status(id)).toMatchObject({
        message,
        state: "failed",
      });
      expect(t.failed.at(-1)?.failure).toEqual({
        message,
        reportedBy: "server",
      });
      return message;
    };
    expect(await refuse(btoa("not a certificate"))).toContain(
      "could not be read"
    );
    expect(await refuse(CERTS.secp256k1)).toContain("not supported");
    expect(await refuse(CERTS.ed25519)).toContain("not supported");
    expect(
      await refuse(CERTS.rsa, { expectedCertificateSha256: sha256Hex(CERTS.p256, "base64") })
    ).toContain("not the certificate");
    expect(await refuse(CERTS.p384, { digestAlgorithm: "sha256" })).toContain(
      "digest"
    );
    t.fake.untrusted.add(CERTS.p256);
    expect(await refuse(CERTS.p256)).toContain("trusted");
    expect(await refuse(CERTS.rsa, { fieldName: "missing" })).toBe(
      "The PDF has no empty field missing"
    );
    t.advance(10 * 365 * 24 * 60 * 60 * 1000);
    expect(await refuse(CERTS.rsa)).toContain("not valid now");
  });

  test("checks the certificate again in round 2 and refuses it if no longer trusted", async () => {
    const t = setup();
    const unchecked = await t.preparedJob();
    t.fake.revocationUnchecked.add(CERTS.rsa);
    const accepted = await t.post(unchecked.token, "signature", {
      claimNonce: unchecked.claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(accepted.status).toBe(200);
    expect(t.completed[0]?.result.certificate.revocationChecked).toBe(false);

    const revoked = await t.preparedJob();
    t.fake.untrusted.add(CERTS.rsa);
    const finishes = t.fake.calls.filter(
      (call) => call.path === "/sign/finish"
    ).length;
    const refused = await t.post(revoked.token, "signature", {
      claimNonce: revoked.claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(refused.status).toBe(422);
    expect((await t.keyseal.status(revoked.id))?.message).toContain("trusted");
    expect(
      t.fake.calls.filter((call) => call.path === "/sign/finish").length
    ).toBe(finishes);
  });

  test("422 for a refused signature fails the job", async () => {
    const t = setup();
    const { id, token, claimNonce } = await t.preparedJob();
    const response = await t.post(token, "signature", {
      claimNonce,
      signatures: [btoa("bad")],
    });
    expect(response.status).toBe(422);
    expect(await t.keyseal.status(id)).toMatchObject({
      message:
        "The signature doesn't match the certificate: was the right token used?",
      state: "failed",
    });
    expect(t.completed).toHaveLength(0);
    expect(t.adapter.blobs.size).toBe(0);
  });

  test("426 below the minimum helper version fails the job", async () => {
    const t = setup({ minHelperVersion: "1.2.0" });
    for (const version of ["1.2.0", "1.10.0", "2.0.0-rc.1"]) {
      const { token } = await t.signJob();
      const response = await t.send("GET", t.jobPath(token), {
        headers: { "X-KeySeal-Version": version },
      });
      expect(response.status).toBe(200);
    }
    for (const version of ["1.1.9", "1.2.0-beta", "garbage", ""]) {
      const { id, token } = await t.signJob();
      const response = await t.send("GET", t.jobPath(token), {
        headers: { "X-KeySeal-Version": version },
      });
      expect(response.status).toBe(426);
      expect(await response.json()).toEqual({
        message: "Update the signing helper, then try again.",
        minVersion: "1.2.0",
      });
      expect(await t.keyseal.status(id)).toMatchObject({
        message: "Update the signing helper, then try again.",
        state: "failed",
      });
    }
    expect(t.failed.map(({ failure }) => failure.reportedBy)).toEqual(
      Array(4).fill("server")
    );
    // 426 comes before the job lookup.
    const unknown = await t.send("GET", t.jobPath("b".repeat(43)), {
      headers: { "X-KeySeal-Version": "0.1.0" },
    });
    expect(unknown.status).toBe(426);
  });

  test("426 for an old helper fails a claimed job only from the claiming helper", async () => {
    const t = setup({ minHelperVersion: "1.0.0" });
    const old = { "X-KeySeal-Version": "0.9.0" };
    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    // The token alone, as from a leaked link, cannot end the job.
    expect(
      (await t.send("GET", t.jobPath(token), { headers: old })).status
    ).toBe(426);
    const document = await t.send("GET", t.jobPath(token, "documents/0"), {
      headers: {
        ...old,
        Authorization: `Bearer ${token}`,
        "X-KeySeal-Claim": claimNonce!,
      },
    });
    expect(document.status).toBe(426);
    const wrongNonce = await t.send("POST", t.jobPath(token, "failure"), {
      body: { claimNonce: "w".repeat(43), message: "No." },
      headers: old,
    });
    expect(wrongNonce.status).toBe(426);
    expect(await t.keyseal.status(id)).toEqual({
      expiresAt: expect.any(Date),
      kind: "sign",
      reference: null,
      state: "claimed",
    });

    const own = await t.send("POST", t.jobPath(token, "failure"), {
      body: { claimNonce, message: "No." },
      headers: old,
    });
    expect(own.status).toBe(426);
    expect(await t.keyseal.status(id)).toMatchObject({
      message: "Update the signing helper, then try again.",
      state: "failed",
    });
  });

  test("429 when the rate limit refuses, before anything else", async () => {
    const t = setup({ rateLimit: () => false });
    const response = await t.send("GET", t.jobPath("short"));
    expect(response.status).toBe(429);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  test("502 when the service is unreachable leaves the job for a retry", async () => {
    const t = setup();
    const { token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    t.fake.down = true;
    const body = { certificate: CERTS.rsa, chain: [], claimNonce };
    expect((await t.post(token, "certificate", body)).status).toBe(502);
    expect(await t.jobFor(token)).toMatchObject({
      leaseStartedAt: null,
      state: "claimed",
    });
    t.fake.down = false;
    expect((await t.post(token, "certificate", body)).status).toBe(200);
  });

  test("502 for a service answer other than 400 or 422 leaves the job for a retry", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    const body = { certificate: CERTS.rsa, chain: [], claimNonce };
    for (const status of [401, 404, 500]) {
      t.fake.status = status;
      expect((await t.post(token, "certificate", body)).status).toBe(502);
      expect(await t.jobFor(token)).toMatchObject({
        leaseStartedAt: null,
        state: "claimed",
      });
    }
    t.fake.status = 400;
    expect((await t.post(token, "certificate", body)).status).toBe(422);
    expect(await t.keyseal.status(id)).toMatchObject({
      message: "Refused",
      state: "failed",
    });
  });

  test("502 when the service fails mid-body or answers without JSON", async () => {
    const t = setup();
    const { token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    const body = { certificate: CERTS.rsa, chain: [], claimNonce };
    const answers = [
      () =>
        new Response(
          new ReadableStream({
            pull(controller) {
              controller.error(new DOMException("timed out", "AbortError"));
            },
          }),
          { headers: { "Content-Type": "application/json" } }
        ),
      () => new Response("not json"),
      () => Response.json([1]),
    ];
    for (const answer of answers) {
      t.fake.answer = answer;
      expect((await t.post(token, "certificate", body)).status).toBe(502);
      expect(await t.jobFor(token)).toMatchObject({
        leaseStartedAt: null,
        state: "claimed",
      });
    }
    t.fake.answer = null;
    expect((await t.post(token, "certificate", body)).status).toBe(200);
  });

  test("a service refusal message is cut to 500 characters", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    t.fake.answer = () =>
      Response.json({ detail: "x".repeat(600) }, { status: 422 });
    const response = await t.post(token, "certificate", {
      certificate: CERTS.rsa,
      chain: [],
      claimNonce,
    });
    expect(response.status).toBe(422);
    const status = await t.keyseal.status(id);
    expect(status?.state).toBe("failed");
    expect(status?.message).toBe("x".repeat(500));
  });

  test("a failing onCompleted leaves the job prepared so the helper can retry", async () => {
    const t = setup({ failCompletion: true });
    const { token, claimNonce } = await t.preparedJob();
    const body = { claimNonce, signatures: [GOOD_SIGNATURE] };
    expect((await t.post(token, "signature", body)).status).toBe(500);
    expect(await t.jobFor(token)).toMatchObject({
      leaseStartedAt: null,
      state: "prepared",
    });
    t.state.failCompletion = false;
    expect((await t.post(token, "signature", body)).status).toBe(200);
    expect(t.completed).toHaveLength(1);
    expect(t.failed).toHaveLength(0);
  });

  test("422 when onCompleted throws JobRefused fails the job with its message", async () => {
    const t = setup();
    t.state.refuseCompletion = "The certificate is not in the signer's name.";
    const { id, token, claimNonce } = await t.preparedJob();
    const response = await t.post(token, "signature", {
      claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({
      message: "The certificate is not in the signer's name.",
    });
    expect(await t.keyseal.status(id)).toMatchObject({
      message: "The certificate is not in the signer's name.",
      state: "failed",
    });
    expect(t.adapter.blobs.size).toBe(0);
    expect(t.failed.map(({ failure }) => failure)).toEqual([
      {
        message: "The certificate is not in the signer's name.",
        reportedBy: "server",
      },
    ]);

    const enrol = await t.keyseal.createEnrolJob({
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    const description = await t.claim(enrol.token);
    const refused = await t.post(enrol.token, "certificate", {
      certificate: CERTS.p384,
      chain: [],
      claimNonce: description.claimNonce,
      proof: proofFor("p384", enrol.jobUrl, description.claimNonce, CERTS.p384),
    });
    expect(refused.status).toBe(422);
    expect(await t.keyseal.status(enrol.id)).toMatchObject({
      message: "The certificate is not in the signer's name.",
      state: "failed",
    });
    expect(t.completed).toHaveLength(0);
  });
});

describe("failure report", () => {
  test("fails the job and surfaces the message in status", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    expect(Object.keys((await t.keyseal.status(id))!).sort()).toEqual([
      "expiresAt",
      "kind",
      "reference",
      "state",
    ]);
    const { claimNonce } = await t.claim(token);
    const response = await t.post(token, "failure", {
      claimNonce,
      message: "  Signing cancelled.  ",
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});
    expect(await t.keyseal.status(id)).toMatchObject({
      message: "Signing cancelled.",
      state: "failed",
    });
    expect(t.adapter.blobs.size).toBe(0);
    expect(t.failed).toHaveLength(1);
    expect(t.failed[0]).toMatchObject({
      failure: { message: "Signing cancelled.", reportedBy: "helper" },
      job: { state: "claimed" },
    });
  });

  test("an onFailed error is logged and the job fails anyway", async () => {
    const t = setup();
    t.state.failOnFailed = true;
    const { token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    const errorLog = spyOn(console, "error").mockImplementation(() => {});
    try {
      const response = await t.post(token, "failure", {
        claimNonce,
        message: "Signing cancelled.",
      });
      expect(response.status).toBe(200);
      expect(errorLog).toHaveBeenCalledTimes(1);
    } finally {
      errorLog.mockRestore();
    }
    expect(await t.jobFor(token)).toMatchObject({
      error: "Signing cancelled.",
      leaseStartedAt: null,
      state: "failed",
    });
  });

  test("expiry does not call onFailed", async () => {
    const t = setup();
    const { id } = await t.signJob();
    t.advance(JOB_TTL_MS);
    await t.signJob();
    expect((await t.keyseal.status(id))?.state).toBe("expired");
    expect(t.failed).toHaveLength(0);
  });

  test("needs the claim nonce", async () => {
    const t = setup();
    const { id, token } = await t.signJob();
    await t.claim(token);
    const response = await t.post(token, "failure", {
      claimNonce: "q".repeat(43),
      message: "No.",
    });
    expect(response.status).toBe(409);
    expect((await t.keyseal.status(id))?.state).toBe("claimed");
  });
});

describe("settle lease", () => {
  test("answers 409 while held and allows takeover after 5 minutes", async () => {
    const t = setup();
    const { token } = await t.signJob();
    const { claimNonce } = await t.claim(token);
    const body = { certificate: CERTS.rsa, chain: [], claimNonce };
    let open = () => {};
    t.fake.gate = new Promise((resolve) => {
      open = resolve;
    });
    const first = t.post(token, "certificate", body);
    while (!(await t.jobFor(token)).leaseStartedAt) {
      await Bun.sleep(1);
    }
    expect((await t.post(token, "certificate", body)).status).toBe(409);
    expect(
      (await t.post(token, "failure", { claimNonce, message: "No." })).status
    ).toBe(409);

    t.advance(5 * 60 * 1000 + 1);
    t.fake.gate = null;
    const takeover = await t.post(token, "certificate", body);
    expect(takeover.status).toBe(200);

    open();
    // The first request lost its lease, so it leaves the job alone.
    expect((await first).status).toBe(409);
    const job = await t.jobFor(token);
    expect(job).toMatchObject({ leaseStartedAt: null, state: "prepared" });
    // Only the winner's state remains.
    expect([...t.adapter.blobs.keys()]).toEqual([`${job.stateKey}/0`]);
  });
});

/** Starts round 2 held at /sign/finish; resolves once it holds the lease. */
async function heldSignature(
  t: ReturnType<typeof setup>,
  token: string,
  claimNonce: string
) {
  let open = () => {};
  t.fake.finishGate = new Promise((resolve) => {
    open = resolve;
  });
  const response = t.post(token, "signature", {
    claimNonce,
    signatures: [GOOD_SIGNATURE],
  });
  while (!(await t.jobFor(token)).leaseStartedAt) {
    await Bun.sleep(1);
  }
  return { open, response };
}

describe("settle lease races", () => {
  test("two concurrent signatures: one completes, the other gets 409", async () => {
    const t = setup();
    const { token, claimNonce } = await t.preparedJob();
    let open = () => {};
    t.fake.finishGate = new Promise((resolve) => {
      open = resolve;
    });
    const body = { claimNonce, signatures: [GOOD_SIGNATURE] };
    const requests = [
      t.post(token, "signature", body),
      t.post(token, "signature", body),
    ];
    // The gated request cannot answer before the gate opens.
    expect((await Promise.race(requests)).status).toBe(409);
    open();
    const statuses = (await Promise.all(requests)).map((r) => r.status);
    expect(statuses.sort()).toEqual([200, 409]);
    expect(t.completed).toHaveLength(1);
    expect(
      t.fake.calls.filter((call) => call.path === "/sign/finish")
    ).toHaveLength(1);
  });

  test("a sweep past the TTL leaves a job whose lease is live", async () => {
    const t = setup();
    const { token, claimNonce } = await t.preparedJob();
    t.advance(14 * 60 * 1000);
    const round2 = await heldSignature(t, token, claimNonce);
    t.advance(2 * 60 * 1000);
    await t.signJob();
    expect((await t.jobFor(token)).state).toBe("prepared");
    round2.open();
    expect((await round2.response).status).toBe(200);
    expect(t.completed).toHaveLength(1);
    expect((await t.jobFor(token)).state).toBe("completed");
  });

  test("an old helper version cannot fail a job under a live lease", async () => {
    const t = setup({ minHelperVersion: "1.0.0" });
    const old = { "X-KeySeal-Version": "0.9.0" };
    const { token, claimNonce } = await t.preparedJob();
    const round2 = await heldSignature(t, token, claimNonce);
    expect(
      (await t.send("GET", t.jobPath(token), { headers: old })).status
    ).toBe(426);
    const failure = await t.send("POST", t.jobPath(token, "failure"), {
      body: { claimNonce, message: "No." },
      headers: old,
    });
    expect(failure.status).toBe(426);
    expect((await t.jobFor(token)).state).toBe("prepared");
    round2.open();
    expect((await round2.response).status).toBe(200);
    expect(t.completed).toHaveLength(1);
    expect((await t.jobFor(token)).state).toBe("completed");
  });
});

describe("document download", () => {
  test("needs the token and the claim nonce, and the prepared state", async () => {
    const t = setup();
    const { token } = await t.signJob();
    const path = t.jobPath(token, "documents/0");
    const { claimNonce } = await t.claim(token);
    const headers = {
      Authorization: `Bearer ${token}`,
      "X-KeySeal-Claim": claimNonce!,
    };
    expect((await t.send("GET", path, { headers })).status).toBe(409);

    await t.post(token, "certificate", {
      certificate: CERTS.rsa,
      chain: [],
      claimNonce,
    });
    expect((await t.send("GET", path)).status).toBe(403);
    expect(
      (
        await t.send("GET", path, {
          headers: { Authorization: `Bearer ${token}` },
        })
      ).status
    ).toBe(403);
    expect(
      (
        await t.send("GET", path, {
          headers: { "X-KeySeal-Claim": claimNonce! },
        })
      ).status
    ).toBe(403);
    const wrongNonce = { ...headers, "X-KeySeal-Claim": "n".repeat(43) };
    expect((await t.send("GET", path, { headers: wrongNonce })).status).toBe(
      403
    );
    const wrongToken = {
      ...headers,
      Authorization: `Bearer ${"t".repeat(43)}`,
    };
    expect((await t.send("GET", path, { headers: wrongToken })).status).toBe(
      403
    );

    const response = await t.send("GET", path, { headers });
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/pdf");
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.text()).toBe("%PDF-1.7 test document prepared");
    // Only the job's own documents, by index without leading zeros.
    expect(
      (await t.send("GET", t.jobPath(token, "documents/1"), { headers })).status
    ).toBe(404);
    for (const other of [
      "documents/00",
      "documents/-1",
      "documents",
      "document",
    ]) {
      expect(
        (await t.send("GET", t.jobPath(token, other), { headers })).status
      ).toBe(404);
    }

    await t.post(token, "signature", {
      claimNonce,
      signatures: [GOOD_SIGNATURE],
    });
    expect((await t.send("GET", path, { headers })).status).toBe(410);
    expect(
      (
        await t.send("GET", t.jobPath("c".repeat(43), "documents/0"), {
          headers,
        })
      ).status
    ).toBe(404);
  });
});

describe("routing and manifest", () => {
  test("answers 404 outside its routes and honours basePath", async () => {
    const t = setup({ basePath: "/api/keyseal" });
    const { token, jobUrl } = await t.signJob();
    expect(jobUrl).toBe(`${ORIGIN}/api/keyseal/v1/jobs/${token}`);
    expect((await t.send("GET", `/v1/jobs/${token}`)).status).toBe(404);
    expect((await t.send("GET", "/api/keyseal/v1/other")).status).toBe(404);
    expect((await t.send("POST", t.jobPath(token))).status).toBe(404);
    expect((await t.send("GET", t.jobPath(token, "signature"))).status).toBe(
      404
    );
    expect((await t.send("GET", t.jobPath(token))).status).toBe(200);
  });

  test("serves the manifest from branding", async () => {
    const t = setup({
      branding: {
        accentColor: "#1f6feb",
        icon: `${ORIGIN}/icon.png`,
        name: "Example Trust",
        translucent: false,
      },
      minHelperVersion: "1.2.0",
    });
    const response = await t.send("GET", "/.well-known/keyseal.json");
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toStartWith(
      "application/json"
    );
    expect(await response.json()).toEqual({
      accentColor: "#1f6feb",
      icon: `${ORIGIN}/icon.png`,
      minHelperVersion: "1.2.0",
      name: "Example Trust",
      protocol: 1,
      translucent: false,
    });
    expect(setup().keyseal.manifest().status).toBe(404);
  });

});

describe("expiry", () => {
  test("a job whose row can't be created leaves no blob behind", async () => {
    const t = setup();
    const create = t.adapter.create;
    t.adapter.create = async () => {
      throw new Error("storage is down");
    };
    await expect(t.signJob()).rejects.toThrow("storage is down");
    expect(t.adapter.blobs.size).toBe(0);
    t.adapter.create = create;
    await t.signJob();
    expect(t.adapter.blobs.size).toBe(1);
  });

  test("sweep expires old jobs and drops their blobs without a new job", async () => {
    const t = setup();
    const { token } = await t.preparedJob();
    const { token: fresh } = await t.signJob();
    t.advance(14 * 60 * 1000);
    await t.keyseal.sweep();
    expect((await t.jobFor(token)).state).toBe("prepared");
    t.advance(2 * 60 * 1000);
    await t.keyseal.sweep();
    expect((await t.jobFor(token)).state).toBe("expired");
    expect((await t.jobFor(fresh)).state).toBe("expired");
    expect(t.adapter.blobs.size).toBe(0);
    expect(t.adapter.jobs.size).toBe(2);
  });

  test("sweep drops the blobs a failed deletion left on ended jobs", async () => {
    const t = setup();
    const done = await t.preparedJob();
    const deleteBlob = t.adapter.deleteBlob;
    t.adapter.deleteBlob = async () => {
      throw new Error("storage is down");
    };
    // The job completes, then its state blob can't be deleted.
    const body = { claimNonce: done.claimNonce, signatures: [GOOD_SIGNATURE] };
    expect((await t.post(done.token, "signature", body)).status).toBe(500);
    expect((await t.jobFor(done.token)).state).toBe("completed");
    // The sweep expires a job, then can't delete its PDF.
    const { token: old } = await t.signJob();
    t.advance(16 * 60 * 1000);
    await expect(t.keyseal.sweep()).rejects.toThrow("storage is down");
    expect((await t.jobFor(old)).state).toBe("expired");
    expect(t.adapter.blobs.size).toBe(2);
    t.adapter.deleteBlob = deleteBlob;
    const { token: live } = await t.signJob();
    await t.keyseal.sweep();
    expect([...t.adapter.blobs.keys()]).toEqual([`${sha256Hex(live)}/pdf/0`]);
  });

  test("sweep leaves blobs that aren't a job's", async () => {
    const t = setup();
    const foreign = ["backup.pdf", "other/file", `${"g".repeat(64)}/pdf/0`];
    for (const key of foreign) {
      await t.adapter.putBlob(key, Uint8Array.of(1));
    }
    await t.keyseal.sweep();
    expect([...t.adapter.blobs.keys()]).toEqual(foreign);
  });

  test("creating a job expires old ones and drops their blobs", async () => {
    const t = setup();
    const { token } = await t.preparedJob();
    expect(t.adapter.blobs.size).toBe(1);
    t.advance(16 * 60 * 1000);
    await t.signJob();
    expect((await t.jobFor(token)).state).toBe("expired");
    expect(
      [...t.adapter.blobs.keys()].some((key) =>
        key.startsWith(sha256Hex(token))
      )
    ).toBe(false);
  });
});
