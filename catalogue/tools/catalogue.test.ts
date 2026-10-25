import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";

import { signCatalogue, validate, verifyCatalogue } from "./catalogue.ts";

function fixture() {
  return {
    version: 1,
    generatedAt: "2026-10-22T00:00:00Z",
    tokens: [
      {
        name: "Token A",
        vendor: "Vendor A",
        usb: [{ vid: "096e", pid: "0807" }],
        modules: {
          "macos-arm64": ["/usr/local/lib/liba.dylib"],
          "windows-x64": [
            "C:\\Windows\\System32\\a.dll",
            "C:\\Program Files (x86)\\Vendor\\a.dll",
          ],
          "linux-x64": [
            "/usr/lib/liba.so",
            "/usr/lib64/liba.so",
            "/opt/vendor/lib.so",
          ],
        },
      },
      {
        name: "Token B",
        vendor: "Vendor B",
        usb: [] as { vid: string; pid: string }[],
        modules: {
          "macos-x64": [
            "/Library/Frameworks/B.framework/Versions/A/libb.dylib",
            "/Applications/Vendor.app/Contents/libb.dylib",
          ],
        },
        cng: true,
      },
    ],
  };
}

describe("schema", () => {
  test("accepts a valid catalogue", () => {
    expect(validate(fixture())).toEqual([]);
  });

  test("accepts the shipped catalogue", async () => {
    expect(
      validate(
        await Bun.file(new URL("../catalogue.json", import.meta.url)).json()
      )
    ).toEqual([]);
  });

  test.each([
    ["macos-arm64", "/Users/x/lib.dylib"],
    ["macos-arm64", "/Users/alice/lib/liba.dylib"],
    ["macos-arm64", "/Users/alice/Library/liba.dylib"],
    ["macos-arm64", "/tmp/liba.dylib"],
    ["macos-arm64", "/usr/local/lib/../../../tmp/liba.dylib"],
    ["linux-x64", "lib/liba.so"],
    ["linux-x64", "/home/alice/.local/lib/liba.so"],
    ["windows-x64", "C:\\Users\\alice\\AppData\\Local\\a.dll"],
    ["windows-x64", "C:\\Windows\\System32\\..\\Temp\\a.dll"],
    ["windows-x64", "/usr/lib/liba.so"],
  ])("rejects %s path %s", (platform, path) => {
    const catalogue = fixture();
    (catalogue.tokens[0]!.modules as Record<string, string[]>)[platform] = [
      path,
    ];
    expect(validate(catalogue)).not.toEqual([]);
  });

  test("rejects a vid/pid repeated within a token", () => {
    const catalogue = fixture();
    catalogue.tokens[0]!.usb.push({ vid: "096e", pid: "0807" });
    expect(validate(catalogue)).not.toEqual([]);
  });

  test("rejects a vid/pid shared by two tokens", () => {
    const catalogue = fixture();
    catalogue.tokens[1]!.usb.push({ vid: "096e", pid: "0807" });
    expect(validate(catalogue)).toEqual([
      'usb id 096e:0807 appears in both "Token A" and "Token B"',
    ]);
  });

  test("rejects uppercase hex and unknown platforms", () => {
    const upper = fixture();
    upper.tokens[0]!.usb[0]!.vid = "096E";
    expect(validate(upper)).not.toEqual([]);
    const platform = fixture();
    (platform.tokens[0]!.modules as Record<string, string[]>)["linux-arm64"] = [
      "/usr/lib/liba.so",
    ];
    expect(validate(platform)).not.toEqual([]);
  });
});

describe("signing", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey
    .export({ format: "pem", type: "pkcs8" })
    .toString();
  const publicPem = publicKey
    .export({ format: "pem", type: "spki" })
    .toString();
  const bytes = new TextEncoder().encode(JSON.stringify(fixture(), null, 2));

  test("round trips", () => {
    const sig = signCatalogue(bytes, privatePem);
    expect(sig.keyId).toMatch(/^[0-9a-f]{64}$/);
    expect(Buffer.from(sig.signature, "base64")).toHaveLength(64);
    expect(() => verifyCatalogue(bytes, sig, publicPem)).not.toThrow();
  });

  test("key id is the SHA-256 of the raw public key", () => {
    const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    expect(signCatalogue(bytes, privatePem).keyId).toBe(
      new Bun.CryptoHasher("sha256").update(raw).digest("hex")
    );
  });

  test("rejects modified bytes", () => {
    const sig = signCatalogue(bytes, privatePem);
    const tampered = new TextEncoder().encode(
      new TextDecoder().decode(bytes).replace('"version": 1', '"version": 2')
    );
    expect(() => verifyCatalogue(tampered, sig, publicPem)).toThrow(
      "signature does not verify"
    );
  });

  test("rejects a different key", () => {
    const sig = signCatalogue(bytes, privatePem);
    const other = generateKeyPairSync("ed25519")
      .publicKey.export({ format: "pem", type: "spki" })
      .toString();
    expect(() => verifyCatalogue(bytes, sig, other)).toThrow(
      "does not match the public key"
    );
  });

  test("refuses to sign an invalid catalogue", () => {
    const invalid = fixture();
    invalid.tokens[0]!.modules["linux-x64"] = ["/tmp/liba.so"];
    expect(() =>
      signCatalogue(
        new TextEncoder().encode(JSON.stringify(invalid)),
        privatePem
      )
    ).toThrow("invalid");
  });
});
