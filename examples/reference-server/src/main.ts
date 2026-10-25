import {
  createMemoryAdapter,
  createKeySeal,
  ServiceClient,
  ServiceError,
  type CertificatePolicy,
  type RsaPadding,
  type SignatureDetails,
  type SignDocumentInput,
} from "@keyseal/server";

import { page } from "./page.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Set ${name}`);
  }
  return value;
}

const port = Number(process.env.PORT ?? "8787");
const origin = process.env.KEYSEAL_ORIGIN ?? `http://localhost:${port}`;
const outDir = "out";

const service = new ServiceClient({
  token: required("SIGNING_SERVICE_TOKEN"),
  url: required("SIGNING_SERVICE_URL"),
});

/** Where the signed PDF of a job's document `index` is written. */
function outputPath(reference: string | null, index: number): string {
  return `${outDir}/${reference}-${index}.pdf`;
}

const adapter = createMemoryAdapter({
  async onCompleted(job, result) {
    if (result.kind === "sign") {
      for (const [index, pdf] of result.pdfs.entries()) {
        await Bun.write(outputPath(job.reference, index), pdf);
      }
    }
  },
});

const keyseal = createKeySeal({
  adapter,
  // The default origin is http://localhost; an https KEYSEAL_ORIGIN is unaffected.
  allowInsecureOrigin: true,
  branding: { name: "KeySeal reference server" },
  origin,
  service,
  ...(process.env.KEYSEAL_MIN_HELPER_VERSION
    ? { minHelperVersion: process.env.KEYSEAL_MIN_HELPER_VERSION }
    : {}),
});

interface DocumentRequest {
  /** Base64 PDF. */
  pdf?: unknown;
  title?: unknown;
  /** An existing empty signature field; without it one is added on the last page. */
  fieldName?: unknown;
  /** `{ reason?, location?, contactInfo? }`, checked by `createSignJob`. */
  signatureDetails?: unknown;
}

interface JobRequest {
  title?: unknown;
  signer?: unknown;
  /** The PDFs to sign together. */
  documents?: unknown;
  expectedCertificateSha256?: unknown;
  /** Checked by `@keyseal/server`. */
  certificatePolicy?: unknown;
  rsaPadding?: unknown;
}

/** A document of the request, with a signature field added when it names none. */
async function signDocument(
  entry: DocumentRequest,
  fieldName: string
): Promise<SignDocumentInput> {
  let pdf: Uint8Array = Buffer.from(entry.pdf as string, "base64");
  let field = typeof entry.fieldName === "string" ? entry.fieldName : "";
  if (!field) {
    field = fieldName;
    pdf = await service.prepare(pdf, [
      { box: [36, 36, 236, 96], name: field, page: -1 },
    ]);
  }
  return {
    fieldName: field,
    pdf,
    ...(typeof entry.title === "string" ? { title: entry.title } : {}),
    ...(entry.signatureDetails === undefined
      ? {}
      : { signatureDetails: entry.signatureDetails as SignatureDetails }),
  };
}

/** `POST /jobs`: creates a sign job for one or more PDFs and returns its link. */
async function createJob(request: Request): Promise<Response> {
  const body = (await request.json().catch(() => null)) as JobRequest | null;
  const entries = body?.documents;
  if (
    !body ||
    !Array.isArray(entries) ||
    !entries.every(
      (entry: DocumentRequest | null) => typeof entry?.pdf === "string"
    )
  ) {
    return Response.json(
      { message: "Send JSON with documents, each with a base64 pdf." },
      { status: 400 }
    );
  }
  const reference = crypto.randomUUID();
  try {
    const field = `keyseal_${reference.replaceAll("-", "")}`;
    const documents: SignDocumentInput[] = [];
    for (const entry of entries as DocumentRequest[]) {
      documents.push(await signDocument(entry, field));
    }
    const created = await keyseal.createSignJob({
      documents,
      reference,
      signer: typeof body.signer === "string" ? body.signer : "Signer",
      title: typeof body.title === "string" ? body.title : "Document",
      ...(typeof body.expectedCertificateSha256 === "string"
        ? { expectedCertificateSha256: body.expectedCertificateSha256 }
        : {}),
      ...(body.certificatePolicy === undefined
        ? {}
        : { certificatePolicy: body.certificatePolicy as CertificatePolicy }),
      ...(body.rsaPadding === "pss" || body.rsaPadding === "pkcs1"
        ? { rsaPadding: body.rsaPadding as RsaPadding }
        : {}),
    });
    return Response.json({
      id: created.id,
      jobUrl: created.jobUrl,
      link: created.link,
      reference,
    });
  } catch (error) {
    if (error instanceof TypeError || error instanceof ServiceError) {
      return Response.json({ message: error.message }, { status: 400 });
    }
    throw error;
  }
}

/** `POST /enrol-jobs`: creates an enrol job that captures a certificate. */
async function createEnrolJob(request: Request): Promise<Response> {
  const body = (await request.json().catch(() => null)) as JobRequest | null;
  if (!body) {
    return Response.json({ message: "Send JSON." }, { status: 400 });
  }
  const reference = crypto.randomUUID();
  try {
    const created = await keyseal.createEnrolJob({
      reference,
      signer: typeof body.signer === "string" ? body.signer : "Signer",
      title: typeof body.title === "string" ? body.title : "Enrolment",
      ...(typeof body.expectedCertificateSha256 === "string"
        ? { expectedCertificateSha256: body.expectedCertificateSha256 }
        : {}),
      ...(body.certificatePolicy === undefined
        ? {}
        : { certificatePolicy: body.certificatePolicy as CertificatePolicy }),
    });
    return Response.json({
      id: created.id,
      jobUrl: created.jobUrl,
      link: created.link,
      reference,
    });
  } catch (error) {
    if (error instanceof TypeError) {
      return Response.json({ message: error.message }, { status: 400 });
    }
    throw error;
  }
}

/** `GET /jobs/:id/status`: what the page polls. */
async function jobStatus(id: string): Promise<Response> {
  const status = await keyseal.status(id);
  const job = await adapter.get(id);
  if (!status || !job) {
    return Response.json({ message: "No such job." }, { status: 404 });
  }
  const outputs =
    status.state === "completed"
      ? job.documents.map((_, index) => outputPath(status.reference, index))
      : null;
  return Response.json(
    { ...status, outputs },
    { headers: { "Cache-Control": "no-store" } }
  );
}

const server = Bun.serve({
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (request.method === "GET" && pathname === "/") {
      return new Response(page, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    if (request.method === "POST" && pathname === "/jobs") {
      return await createJob(request);
    }
    if (request.method === "POST" && pathname === "/enrol-jobs") {
      return await createEnrolJob(request);
    }
    const status = /^\/jobs\/([^/]+)\/status$/.exec(pathname);
    if (request.method === "GET" && status) {
      return await jobStatus(status[1]!);
    }
    return await keyseal.handle(request);
  },
  port,
});

console.log(`keyseal reference server on ${server.url}, job origin ${origin}`);
