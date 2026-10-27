import { describe, expect, spyOn, test } from "bun:test";
import {
  constants,
  createHash,
  createPrivateKey,
  sign,
  X509Certificate,
} from "node:crypto";

import {
  createMemoryAdapter,
  createKeySeal,
  JOB_TTL_MS,
  JobRefused,
  nodeCertificateInspector,
  ServiceClient,
  type CompletedResult,
  type Job,
  type JobFailure,
  type SignDocumentInput,
  type SignJobInput,
  type KeySealOptions,
} from "../src/index.js";

const ORIGIN = "https://dash.example.org";
const SERVICE_TOKEN = "service-token-service-token-service-token";
const START = new Date("2027-01-01T00:00:00Z");
const PDF = new TextEncoder().encode("%PDF-1.7 test document");

async function pem(name: string): Promise<string> {
  return await Bun.file(
    new URL(`fixtures/${name}.pem`, import.meta.url)
  ).text();
}

async function fixture(name: string): Promise<string> {
  return (await pem(name)).replaceAll(/-----[A-Z ]+-----|\s/g, "");
}

/** The private keys of the RSA, P-256 and P-384 certificates. */
const KEYS = {
  p256: createPrivateKey(await pem("p256-key")),
  p384: createPrivateKey(await pem("p384-key")),
  rsa: createPrivateKey(await pem("rsa-key")),
};

/** The fake service's `toSign` for a document with `fieldName`. */
function toSignFor(fieldName: string): string {
  return btoa(`signed attributes ${fieldName}`);
}

/** What the token returns for `toSign`, as protocol section 11.1 encodes it. */
function signWith(
  key: keyof typeof KEYS,
  toSign: string,
  algorithm = key === "rsa" ? "rsa-pkcs1-v1_5" : "ecdsa"
): string {
  const digest = key === "p384" ? "sha384" : "sha256";
  const data = Buffer.from(toSign, "base64");
  const signature =
    algorithm === "ecdsa"
      ? sign(digest, data, { dsaEncoding: "der", key: KEYS[key] })
      : sign(digest, data, {
          key: KEYS[key],
          padding:
            algorithm === "rsa-pss"
              ? constants.RSA_PKCS1_PSS_PADDING
              : constants.RSA_PKCS1_PADDING,
          saltLength: 32,
        });
  return signature.toString("base64");
}

/** The RSA signature of a one-document job with the default field. */
const GOOD_SIGNATURE = signWith("rsa", toSignFor("Signature1"));

const CERTS = {
  ed25519: await fixture("ed25519"),
  p256: await fixture("p256"),
  p384: await fixture("p384"),
  // Issued by "KeySeal Test Sub CA" to O "Acme, Inc.", with policy OIDs
  // 2.16.356.100.2.2 and 2.16.356.100.2.3.
  policy: await fixture("policy"),
  rsa: await fixture("rsa"),
  secp256k1: await fixture("secp256k1"),
};

function sha256(base64: string): string {
  return createHash("sha256")
    .update(Buffer.from(base64, "base64"))
    .digest("hex");
}

/** A stand-in for the signing service's HTTP API. */
function fakeService() {
  const fake = {
    calls: [] as { path: string; body: Record<string, unknown> }[],
    down: false,
    /** Awaited by /sign/start, so a test can hold a request mid-way. */
    gate: null as Promise<void> | null,
    /** Awaited by /sign/finish, likewise. */
    finishGate: null as Promise<void> | null,
    /** Answers every call with this status when set. */
    status: null as number | null,
    /** Answers every call with this response when set. */
    answer: null as (() => Response) | null,
    untrusted: new Set<string>(),
    /** Overrides the signature algorithm /sign/start names. */
    signatureAlgorithm: null as string | null,
    /** /sign/finish awaits `finishGate` only for this field, when set. */
    finishGateField: null as string | null,
    /** /sign/finish refuses the document with this field. */
    refuseFinish: null as string | null,
    /** /sign/start answers 500 for the document with this field. */
    failStart: null as string | null,
    async fetch(input: URL, init: RequestInit): Promise<Response> {
      if (fake.down) {
        throw new TypeError("fetch failed");
      }
      if (fake.status !== null) {
        return Response.json({ detail: "Refused" }, { status: fake.status });
      }
      if (fake.answer !== null) {
        return fake.answer();
      }
      if (
        new Headers(init.headers).get("Authorization") !==
        `Bearer ${SERVICE_TOKEN}`
      ) {
        return Response.json({ detail: "Unauthorized" }, { status: 401 });
      }
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      fake.calls.push({ body, path: input.pathname });
      if (input.pathname === "/certificate") {
        return Response.json({
          trusted: !fake.untrusted.has(body.certificate as string),
        });
      }
      if (input.pathname === "/sign/start") {
        await fake.gate;
        if (body.fieldName === fake.failStart) {
          return Response.json({ detail: "Busy" }, { status: 500 });
        }
        if (body.fieldName === "missing") {
          return Response.json(
            { detail: "The PDF has no empty field missing" },
            { status: 422 }
          );
        }
        const key = new X509Certificate(
          Buffer.from(body.certificate as string, "base64")
        ).publicKey;
        const digest =
          key.asymmetricKeyDetails?.namedCurve === "secp384r1"
            ? "sha384"
            : "sha256";
        const signatureAlgorithm =
          fake.signatureAlgorithm ??
          (key.asymmetricKeyType === "ec"
            ? "ecdsa"
            : body.rsaPadding === "pss"
              ? "rsa-pss"
              : "rsa-pkcs1-v1_5");
        const prepared = `${atob(body.pdf as string)} prepared`;
        return Response.json({
          digestAlgorithm: digest,
          signatureAlgorithm,
          state: JSON.stringify({
            fieldName: body.fieldName,
            output: btoa(prepared),
          }),
          toSign: toSignFor(body.fieldName as string),
        });
      }
      if (input.pathname === "/sign/finish") {
        const state = JSON.parse(body.state as string) as {
          fieldName: string;
          output: string;
        };
        if (
          fake.finishGateField === null ||
          fake.finishGateField === state.fieldName
        ) {
          await fake.finishGate;
        }
        if (state.fieldName === fake.refuseFinish) {
          return Response.json(
            { detail: `The PDF with ${state.fieldName} can't be finished` },
            { status: 422 }
          );
        }
        return new Response(`${atob(state.output)} signed`, {
          headers: { "Content-Type": "application/pdf" },
        });
      }
      return Response.json({ detail: "Not Found" }, { status: 404 });
    },
  };
  return fake;
}

/** A job description as the claim returns it. */
interface Description {
  claimNonce: string;
  documents?: { document: string; title: string }[];
  [member: string]: unknown;
}

type JobOptions = Partial<SignJobInput> &
  Partial<Omit<SignDocumentInput, "title">>;

function setup(
  options: Partial<KeySealOptions> & { failCompletion?: boolean } = {}
) {
  const fake = fakeService();
  const completed: { job: Job; result: CompletedResult }[] = [];
  const failed: { job: Job; failure: JobFailure }[] = [];
  const clock = { now: START };
  const state = {
    failCompletion: options.failCompletion ?? false,
    failOnFailed: false,
    refuseCompletion: null as string | null,
  };
  const adapter = createMemoryAdapter({
    async onCompleted(job, result) {
      if (state.failCompletion) {
        throw new Error("storage is down");
      }
      if (state.refuseCompletion) {
        throw new JobRefused(state.refuseCompletion);
      }
      completed.push({ job, result });
    },
    async onFailed(job, failure) {
      failed.push({ failure, job });
      if (state.failOnFailed) {
        throw new Error("storage is down");
      }
    },
  });
  const keyseal = createKeySeal({
    adapter,
    now: () => clock.now,
    origin: ORIGIN,
    service: new ServiceClient({
      fetch: fake.fetch,
      token: SERVICE_TOKEN,
      url: "http://signing:8080",
    }),
    ...options,
  });
  const basePath = options.basePath ?? "";

  function advance(ms: number): void {
    clock.now = new Date(clock.now.getTime() + ms);
  }

  async function send(
    method: string,
    path: string,
    init: { body?: unknown; headers?: Record<string, string> } = {}
  ): Promise<Response> {
    return await keyseal.handle(
      new Request(`${ORIGIN}${path}`, {
        method,
        ...(init.body === undefined
          ? {}
          : {
              body:
                typeof init.body === "string"
                  ? init.body
                  : JSON.stringify(init.body),
            }),
        headers: {
          "Content-Type": "application/json",
          "X-KeySeal-Version": "1.0.0",
          ...init.headers,
        },
      })
    );
  }

  function jobPath(token: string, action = ""): string {
    return `${basePath}/v1/jobs/${token}${action ? `/${action}` : ""}`;
  }

  async function claim(token: string): Promise<Description> {
    const response = await send("GET", jobPath(token));
    expect(response.status).toBe(200);
    return (await response.json()) as Description;
  }

  async function post(
    token: string,
    action: string,
    body: unknown
  ): Promise<Response> {
    return await send("POST", jobPath(token, action), { body });
  }

  /**
   * A sign job; without `documents`, the document fields given make its one
   * document, in field Signature1 of `PDF` by default.
   */
  async function signJob(input: JobOptions = {}) {
    const { fieldName, pdf, signatureDetails, stampStyle, documents, ...job } =
      input;
    return await keyseal.createSignJob({
      documents: documents ?? [
        {
          fieldName: fieldName ?? "Signature1",
          pdf: pdf ?? PDF,
          ...(signatureDetails === undefined ? {} : { signatureDetails }),
          ...(stampStyle === undefined ? {} : { stampStyle }),
        },
      ],
      signer: "Asha Rao",
      title: "Board resolution 2026/14",
      ...job,
    });
  }

  /** A sign job taken through round 1 with `certificate`. */
  async function preparedJob(certificate = CERTS.rsa, input: JobOptions = {}) {
    const { id, token } = await signJob(input);
    const { claimNonce } = await claim(token);
    const response = await post(token, "certificate", {
      certificate,
      chain: [],
      claimNonce,
    });
    expect(response.status).toBe(200);
    return {
      claimNonce: claimNonce!,
      id,
      prepared: await response.json(),
      token,
    };
  }

  async function jobFor(token: string): Promise<Job> {
    return (await adapter.get(sha256Hex(token)))!;
  }

  return {
    adapter,
    advance,
    claim,
    completed,
    failed,
    fake,
    jobFor,
    jobPath,
    post,
    preparedJob,
    send,
    signJob,
    keyseal,
    state,
  };
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

describe("sign flow", () => {
  test("completes both rounds and hands the signed PDF to onCompleted", async () => {
    const t = setup();
    const expected = sha256(CERTS.rsa);
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

/** Three documents, each in its own field and with its own title. */
const BATCH: SignDocumentInput[] = [1, 2, 3].map((n) => ({
  fieldName: `Signature${n}`,
  pdf: new TextEncoder().encode(`%PDF-1.7 document ${n}`),
  title: `Document ${n}`,
}));

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
});

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
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});
    expect(t.completed[0]?.result).toMatchObject({
      certificate: {
        key: { curve: "P-384", type: "ec" },
        sha256: sha256(CERTS.p384),
      },
      kind: "enrol",
    });
    expect((await t.keyseal.status(id))?.state).toBe("completed");
    expect(t.fake.calls.map((call) => call.path)).toEqual(["/certificate"]);
  });

  test("refuses a certificate other than the expected one", async () => {
    const t = setup();
    const { id, token } = await t.keyseal.createEnrolJob({
      expectedCertificateSha256: sha256(CERTS.rsa),
      signer: "Asha Rao",
      title: "DSC enrolment",
    });
    const { claimNonce } = await t.claim(token);
    const response = await t.post(token, "certificate", {
      certificate: CERTS.p256,
      chain: [],
      claimNonce,
    });
    expect(response.status).toBe(422);
    expect((await t.keyseal.status(id))?.state).toBe("failed");
  });
});

describe("certificate policy", () => {
  const POLICY = {
    issuerCommonNames: ["Other CA", "KeySeal Test Sub CA"],
    policyOids: ["2.16.356.100.2.3"],
    subjectOrganization: "Acme, Inc.",
  };

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
    const t = setup();
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
      await refuse(CERTS.rsa, { expectedCertificateSha256: sha256(CERTS.p256) })
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

  test("rejects invalid options and job input", async () => {
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
    ]) {
      expect(() => setup({ basePath })).toThrow(TypeError);
    }
    expect(() => setup({ basePath: "/api/keyseal_v1.0~x" })).not.toThrow();
    expect(() => setup({ minHelperVersion: "1.2" })).toThrow(TypeError);
    expect(() =>
      setup({ branding: { icon: "https://other.example/icon.png", name: "X" } })
    ).toThrow(TypeError);
    const t = setup();
    expect(t.signJob({ title: "" })).rejects.toThrow(TypeError);
    expect(t.signJob({ fieldName: "bad name" })).rejects.toThrow(TypeError);
    expect(t.signJob({ expectedCertificateSha256: "ABC" })).rejects.toThrow(
      TypeError
    );
    expect(
      t.signJob({ pdf: new Uint8Array(25 * 1024 * 1024 + 1) })
    ).rejects.toThrow(TypeError);
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
