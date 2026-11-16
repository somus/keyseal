import { describe, expect, test } from "bun:test";

import { ServiceClient } from "../src/index.js";
import { GOOD_SIGNATURE, PDF, SERVICE_TOKEN, setup } from "./support.js";

describe("service client", () => {
  test("sends base and keyUsage as validate query parameters", async () => {
    const paths: string[] = [];
    const service = new ServiceClient({
      async fetch(input) {
        paths.push(`${input.pathname}${input.search}`);
        return Response.json({ signatures: [], status: "no_signatures" });
      },
      token: SERVICE_TOKEN,
      url: "http://signing:8080",
    });
    const pdf = new Uint8Array(PDF);
    await service.validate(pdf);
    await service.validate(pdf, 1234);
    await service.validate(pdf, undefined, "digitalSignature");
    await service.validate(pdf, 1234, "nonRepudiation");
    expect(paths).toEqual([
      "/validate",
      "/validate?base=1234",
      "/validate?keyUsage=digitalSignature",
      "/validate?base=1234&keyUsage=nonRepudiation",
    ]);
  });

  test("createKeySeal takes any object with the calls it makes", async () => {
    const calls: string[] = [];
    let client: ServiceClient | undefined;
    const t = setup({
      service: {
        async certificate(input) {
          calls.push("certificate");
          return await client!.certificate(input);
        },
        async signFinish(input) {
          calls.push("signFinish");
          return await client!.signFinish(input);
        },
        async signStart(input) {
          calls.push("signStart");
          return await client!.signStart(input);
        },
      },
    });
    client = new ServiceClient({
      fetch: t.fake.fetch,
      token: SERVICE_TOKEN,
      url: "http://signing:8080",
    });
    const { token, claimNonce } = await t.preparedJob();
    const body = { claimNonce, signatures: [GOOD_SIGNATURE] };
    expect((await t.post(token, "signature", body)).status).toBe(200);
    expect(t.completed).toHaveLength(1);
    expect(calls).toEqual([
      "certificate",
      "signStart",
      "certificate",
      "signFinish",
    ]);
  });
});
