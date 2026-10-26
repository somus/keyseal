// Development signing only. Production signatures come from helper/packaging/sign-file.sh (catalogue/README.md).
// Usage: bun tools/sign.ts <private-key.pem> [catalogue.json]
import { signCatalogue } from "./catalogue.ts";

const [keyPath, cataloguePath = "catalogue.json"] = process.argv.slice(2);
if (keyPath === undefined) {
  console.error("usage: bun tools/sign.ts <private-key.pem> [catalogue.json]");
  process.exit(2);
}

const bytes = await Bun.file(cataloguePath).bytes();
const sig = signCatalogue(bytes, await Bun.file(keyPath).text());
await Bun.write(`${cataloguePath}.sig`, `${JSON.stringify(sig, null, 2)}\n`);
console.log(`signed ${cataloguePath} with key ${sig.keyId}`);
