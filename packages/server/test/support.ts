// Fixtures and helpers the server tests share.
import { expect } from "bun:test";
import { constants, createHash, createPrivateKey, sign } from "node:crypto";

import {
  createMemoryAdapter,
  createKeySeal,
  JobRefused,
  nodeCertificateInspector,
  ServiceClient,
  type CertificateInspector,
  type CompletedResult,
  type Job,
  type JobFailure,
  type SignDocumentInput,
  type SignJobInput,
  type KeySealOptions,
} from "../src/index.js";

export const ORIGIN = "https://dash.example.org";
export const SERVICE_TOKEN = "service-token-service-token-service-token";
export const START = new Date("2027-01-01T00:00:00Z");
export const PDF = new TextEncoder().encode("%PDF-1.7 test document");

export async function pem(name: string): Promise<string> {
  return await Bun.file(
    new URL(`fixtures/${name}.pem`, import.meta.url)
  ).text();
}

async function fixture(name: string): Promise<string> {
  return (await pem(name)).replaceAll(/-----[A-Z ]+-----|\s/g, "");
}

/** The private keys of the RSA, P-256 and P-384 certificates. */
export const KEYS = {
  p256: createPrivateKey(await pem("p256-key")),
  p384: createPrivateKey(await pem("p384-key")),
  rsa: createPrivateKey(await pem("rsa-key")),
};

/** The fake service's `toSign` for a document with `fieldName`. */
export function toSignFor(fieldName: string): string {
  return btoa(`signed attributes ${fieldName}`);
}

/** What the token returns for `toSign`, as protocol section 11.1 encodes it. */
export function signWith(
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
export const GOOD_SIGNATURE = signWith("rsa", toSignFor("Signature1"));

export const CERTS = {
  brainpoolP256r1: await fixture("brainpoolP256r1"),
  brainpoolP384r1: await fixture("brainpoolP384r1"),
  ed25519: await fixture("ed25519"),
  p256: await fixture("p256"),
  p384: await fixture("p384"),
  // Issued by "KeySeal Test Sub CA" to O "Acme, Inc.", with policy OIDs
  // 2.16.356.100.2.2 and 2.16.356.100.2.3.
  policy: await fixture("policy"),
  rsa: await fixture("rsa"),
  secp256k1: await fixture("secp256k1"),
  // Self-signed P-256 certificates to O "Acme, Inc.": end-entity ones whose
  // KeyUsage asserts digitalSignature only, nonRepudiation only, or that have
  // no KeyUsage, and a CA certificate asserting nonRepudiation.
  "usage-ca": await fixture("usage-ca"),
  "usage-none": await fixture("usage-none"),
  "usage-nonrepudiation": await fixture("usage-nonrepudiation"),
  "usage-signature": await fixture("usage-signature"),
};

/**
 * Each brainpool key's signature over `toSignFor("Signature1")`, made by
 * OpenSSL: Bun's `node:crypto` cannot sign with these curves.
 */
export const BRAINPOOL_SIGNATURES = {
  brainpoolP256r1: Buffer.from(
    await Bun.file(
      new URL("fixtures/brainpoolP256r1.sig", import.meta.url)
    ).bytes()
  ).toString("base64"),
  brainpoolP384r1: Buffer.from(
    await Bun.file(
      new URL("fixtures/brainpoolP384r1.sig", import.meta.url)
    ).bytes()
  ).toString("base64"),
};


/**
 * An enrol proof as the helper sends it (protocol section 8.6): `key` signs
 * the job URL, claim nonce and SHA-256 of `certificate` behind a fixed label.
 */
export function proofFor(
  key: keyof typeof KEYS,
  jobUrl: string,
  claimNonce: string,
  certificate: string
): string {
  const message = `KeySeal enrol proof v1\0${jobUrl}\0${claimNonce}\0${sha256Hex(certificate, "base64")}`;
  return signWith(key, Buffer.from(message).toString("base64"));
}

/**
 * Verifies every signature, for the certificates whose keys the fixtures
 * lack, so an enrol job can take any proof.
 */
export const ANY_PROOF: CertificateInspector = {
  inspect: (der) => nodeCertificateInspector.inspect(der),
  verify: () => true,
};

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
    /** /certificate says these were trusted without a revocation check. */
    revocationUnchecked: new Set<string>(),
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
          revocationChecked: !fake.revocationUnchecked.has(
            body.certificate as string
          ),
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
        // Bun's X509Certificate cannot decode brainpool keys.
        const key = nodeCertificateInspector.inspect(
          Buffer.from(body.certificate as string, "base64")
        )?.key;
        const digest =
          key?.type === "ec" &&
          (key.curve === "P-384" || key.curve === "brainpoolP384r1")
            ? "sha384"
            : "sha256";
        const signatureAlgorithm =
          fake.signatureAlgorithm ??
          (key?.type === "ec"
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
export interface Description {
  claimNonce: string;
  documents?: { document: string; title: string }[];
  [member: string]: unknown;
}

export type JobOptions = Partial<SignJobInput> &
  Partial<Omit<SignDocumentInput, "title">>;

export function setup(
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

/** SHA-256 hex of `data`, UTF-8 text unless `encoding` says otherwise. */
export function sha256Hex(
  data: string,
  encoding: BufferEncoding = "utf8"
): string {
  return createHash("sha256").update(Buffer.from(data, encoding)).digest("hex");
}


/** Three documents, each in its own field and with its own title. */
export const BATCH: SignDocumentInput[] = [1, 2, 3].map((n) => ({
  fieldName: `Signature${n}`,
  pdf: new TextEncoder().encode(`%PDF-1.7 document ${n}`),
  title: `Document ${n}`,
}));
