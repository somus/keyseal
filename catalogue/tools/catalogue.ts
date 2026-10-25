import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

import addFormats from "ajv-formats";
import { Ajv2020 } from "ajv/dist/2020.js";

import schema from "../schema.json" with { type: "json" };

export interface Signature {
  keyId: string;
  signature: string;
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats.default(ajv);
const validateSchema = ajv.compile(schema);

/** Returns every problem found; an empty list means the catalogue is valid. */
export function validate(catalogue: unknown): string[] {
  if (!validateSchema(catalogue)) {
    return (validateSchema.errors ?? []).map(
      (e) => `${e.instancePath || "/"} ${e.message ?? "invalid"}`
    );
  }
  const errors: string[] = [];
  const seen = new Map<string, string>();
  for (const token of (
    catalogue as {
      tokens: { name: string; usb: { vid: string; pid: string }[] }[];
    }
  ).tokens) {
    for (const { vid, pid } of token.usb) {
      const id = `${vid}:${pid}`;
      const owner = seen.get(id);
      if (owner !== undefined)
        errors.push(
          `usb id ${id} appears in both "${owner}" and "${token.name}"`
        );
      else seen.set(id, token.name);
    }
  }
  return errors;
}

export function parseAndValidate(bytes: Uint8Array): void {
  const errors = validate(JSON.parse(new TextDecoder().decode(bytes)));
  if (errors.length > 0)
    throw new Error(`catalogue.json is invalid:\n${errors.join("\n")}`);
}

/** Hex SHA-256 of the raw 32-byte Ed25519 public key. */
export function keyId(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || jwk.x === undefined)
    throw new Error("key is not Ed25519");
  return createHash("sha256")
    .update(Buffer.from(jwk.x, "base64url"))
    .digest("hex");
}

export function signCatalogue(
  bytes: Uint8Array,
  privateKeyPem: string
): Signature {
  parseAndValidate(bytes);
  const privateKey = createPrivateKey(privateKeyPem);
  return {
    keyId: keyId(createPublicKey(privateKey)),
    signature: sign(null, bytes, privateKey).toString("base64"),
  };
}

export function verifyCatalogue(
  bytes: Uint8Array,
  sig: Signature,
  publicKeyPem: string
): void {
  const publicKey = createPublicKey(publicKeyPem);
  if (sig.keyId !== keyId(publicKey))
    throw new Error(
      `signature keyId ${sig.keyId} does not match the public key`
    );
  if (!verify(null, bytes, publicKey, Buffer.from(sig.signature, "base64")))
    throw new Error("signature does not verify");
  parseAndValidate(bytes);
}
