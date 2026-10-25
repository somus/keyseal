// Usage: bun tools/verify.ts <public-key.pem> [catalogue.json]
// Reads <catalogue.json>.sig, checks the key id and signature, then validates the catalogue.
import { verifyCatalogue, type Signature } from "./catalogue.ts";

const [keyPath, cataloguePath = "catalogue.json"] = process.argv.slice(2);
if (keyPath === undefined) {
  console.error("usage: bun tools/verify.ts <public-key.pem> [catalogue.json]");
  process.exit(2);
}

const bytes = await Bun.file(cataloguePath).bytes();
const sig = (await Bun.file(`${cataloguePath}.sig`).json()) as Signature;
verifyCatalogue(bytes, sig, await Bun.file(keyPath).text());
console.log(`${cataloguePath} verified with key ${sig.keyId}`);
