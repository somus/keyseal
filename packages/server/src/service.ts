import { fromBase64, isBase64, readBody, toBase64 } from "./encoding.js";
import type {
  DigestAlgorithm,
  RsaPadding,
  SignatureAlgorithm,
  SignatureDetails,
} from "./types.js";

/** The service refuses larger PDFs. */
export const MAX_PDF_BYTES = 25 * 1024 * 1024;

/** Upper bound on any service response; the sign state holds the PDF in base64. */
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

/** A refusal (`status` 400 or 422) or any other failure (`status` 0 when unreachable). */
export class ServiceError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ServiceError";
    this.status = status;
  }
}

export interface ServiceClientOptions {
  /** Base URL of the signing service, such as `http://signing:8080`. */
  url: string;
  /** The service's `SIGNING_SERVICE_TOKEN`. */
  token: string;
  fetch?: (input: URL, init: RequestInit) => Promise<Response>;
  /** Per request; defaults to 60 seconds. */
  timeoutMs?: number;
}

export interface SignStartInput {
  pdf: Uint8Array;
  fieldName: string;
  certificate: string;
  chain: string[];
  stampStyle?: string;
  rsaPadding?: RsaPadding;
  signatureDetails?: SignatureDetails;
}

export interface SignStartResult {
  /** Base64 DER SignedAttributes. */
  toSign: string;
  digestAlgorithm: DigestAlgorithm;
  signatureAlgorithm: SignatureAlgorithm;
  /** Opaque; hand back unchanged to `signFinish`. */
  state: string;
}

export interface PrepareField {
  name: string;
  /** 0-based; negative counts from the last page. */
  page: number;
  box: [number, number, number, number];
}

export interface ValidatedSignature {
  fieldName: string;
  intact: boolean;
  trusted: boolean;
  /** Whether revocation data for the signer's path checked out; see `CertificateFacts.revocationChecked`. */
  revocationChecked: boolean;
  coversWholeRevision: boolean;
  timestamped: boolean;
  sha256Fingerprint: string;
  signerName: string | null;
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string | null;
  notAfter: string | null;
  signingTime: string | null;
  modificationLevel: string | null;
  error?: string;
}

export interface ValidationReport {
  status: "valid" | "invalid" | "no_signatures";
  checkedAt: string;
  message?: string;
  signatures: ValidatedSignature[];
  textFields: Record<string, string>;
}

async function readLimited(
  response: Response,
  limit: number
): Promise<Uint8Array<ArrayBuffer>> {
  const bytes = await readBody(response.body, limit);
  if (!bytes) {
    throw new ServiceError(
      "The signing service answered with too much data.",
      502
    );
  }
  return bytes;
}

/** Typed calls to the signing service (`service/`), with its bearer token. */
export class ServiceClient {
  readonly #url: string;
  readonly #token: string;
  readonly #fetch: (input: URL, init: RequestInit) => Promise<Response>;
  readonly #timeoutMs: number;

  constructor(options: ServiceClientOptions) {
    this.#url = options.url;
    this.#token = options.token;
    this.#fetch = options.fetch ?? ((input, init) => fetch(input, init));
    this.#timeoutMs = options.timeoutMs ?? 60_000;
  }

  async #post(
    path: string,
    body: BodyInit,
    contentType: string
  ): Promise<Uint8Array<ArrayBuffer>> {
    let response: Response;
    let bytes: Uint8Array<ArrayBuffer>;
    try {
      response = await this.#fetch(new URL(path, this.#url), {
        body,
        headers: {
          Authorization: `Bearer ${this.#token}`,
          "Content-Type": contentType,
        },
        method: "POST",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      // The timeout or a dropped connection can also fail mid-body.
      bytes = await readLimited(response, MAX_RESPONSE_BYTES);
    } catch (cause) {
      if (cause instanceof ServiceError) {
        throw cause;
      }
      throw new ServiceError("The signing service could not be reached.", 0);
    }
    if (!response.ok) {
      let detail: unknown = null;
      try {
        detail = (
          JSON.parse(new TextDecoder().decode(bytes)) as { detail?: unknown }
        ).detail;
      } catch {
        detail = null;
      }
      throw new ServiceError(
        typeof detail === "string"
          ? detail
          : `The signing service answered ${response.status}.`,
        response.status
      );
    }
    return bytes;
  }

  /** A JSON object answer, or a 502 `ServiceError` for anything else. */
  async #postJson(
    path: string,
    body: unknown
  ): Promise<Record<string, unknown>> {
    const bytes = await this.#post(
      path,
      JSON.stringify(body),
      "application/json"
    );
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      parsed = null;
    }
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      throw new ServiceError(
        "The signing service answered with something other than JSON.",
        502
      );
    }
    return parsed as Record<string, unknown>;
  }

  /**
   * Whether the certificate chains to a configured root and may sign, and
   * whether its revocation status was checked.
   */
  async certificate(input: {
    certificate: string;
    chain: string[];
  }): Promise<{ trusted: boolean; revocationChecked: boolean }> {
    const body = await this.#postJson("/certificate", input);
    return {
      revocationChecked: body.revocationChecked === true,
      trusted: body.trusted === true,
    };
  }

  /** Adds empty signature fields to a PDF. */
  async prepare(pdf: Uint8Array, fields: PrepareField[]): Promise<Uint8Array> {
    if (pdf.byteLength > MAX_PDF_BYTES) {
      throw new ServiceError("The PDF is larger than 25 MiB.", 413);
    }
    return await this.#post(
      "/prepare",
      JSON.stringify({ fields, pdf: toBase64(pdf) }),
      "application/json"
    );
  }

  /** Reserves the signature in `fieldName` and returns what the token signs. */
  async signStart(input: SignStartInput): Promise<SignStartResult> {
    if (input.pdf.byteLength > MAX_PDF_BYTES) {
      throw new ServiceError("The PDF is larger than 25 MiB.", 413);
    }
    const body = (await this.#postJson("/sign/start", {
      certificate: input.certificate,
      chain: input.chain,
      fieldName: input.fieldName,
      pdf: toBase64(input.pdf),
      ...(input.rsaPadding ? { rsaPadding: input.rsaPadding } : {}),
      ...(input.stampStyle ? { stampStyle: input.stampStyle } : {}),
      ...input.signatureDetails,
    })) as Partial<Record<keyof SignStartResult, unknown>>;
    const { digestAlgorithm, signatureAlgorithm, state, toSign } = body;
    if (
      typeof toSign !== "string" ||
      !isBase64(toSign) ||
      typeof state !== "string" ||
      (digestAlgorithm !== "sha256" && digestAlgorithm !== "sha384") ||
      (signatureAlgorithm !== "rsa-pkcs1-v1_5" &&
        signatureAlgorithm !== "rsa-pss" &&
        signatureAlgorithm !== "ecdsa")
    ) {
      throw new ServiceError(
        "The signing service answered /sign/start unexpectedly.",
        502
      );
    }
    return { digestAlgorithm, signatureAlgorithm, state, toSign };
  }

  /** Builds the CMS around the token's signature and returns the signed PDF. */
  async signFinish(input: {
    state: string;
    signature: string;
  }): Promise<Uint8Array> {
    return await this.#post(
      "/sign/finish",
      JSON.stringify(input),
      "application/json"
    );
  }

  /** The service's validation report for a PDF; `base` is the length of the copy the signer was given. */
  async validate(
    pdf: Uint8Array<ArrayBuffer>,
    base?: number
  ): Promise<ValidationReport> {
    const path = base === undefined ? "/validate" : `/validate?base=${base}`;
    const bytes = await this.#post(path, new Blob([pdf]), "application/pdf");
    return JSON.parse(new TextDecoder().decode(bytes)) as ValidationReport;
  }
}

/**
 * The prepared PDF inside a `/sign/start` state: the document with the
 * signature placeholder `toSign` was computed for. The service's state is a
 * JSON object whose `output` member is that PDF in base64.
 */
export function preparedDocument(
  state: string
): Uint8Array<ArrayBuffer> | null {
  try {
    const output = (JSON.parse(state) as { output?: unknown }).output;
    return typeof output === "string" && isBase64(output)
      ? fromBase64(output)
      : null;
  } catch {
    return null;
  }
}
