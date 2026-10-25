import { afterEach, beforeEach, describe, expect, jest, test } from "bun:test";

import {
  helperDownloadFor,
  launchHelper,
  signWithHelper,
  watchJob,
  type JobState,
  type JobStatus,
} from "../src/index.js";

const TOKEN = "q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk";
const JOB = `https://dash.example.org/api/keyseal/v1/jobs/${TOKEN}`;
const link = (job: string, action = "sign") =>
  `keyseal://${action}?job=${encodeURIComponent(job)}`;

const frames: {
  hidden: boolean;
  src: string;
  removed: boolean;
  remove(): void;
}[] = [];
(globalThis as Record<string, unknown>).document = {
  createElement: () => ({
    hidden: false,
    src: "",
    removed: false,
    remove() {
      this.removed = true;
    },
  }),
  body: { append: (frame: (typeof frames)[number]) => frames.push(frame) },
};

beforeEach(() => {
  frames.length = 0;
  jest.useFakeTimers();
});
afterEach(() => {
  jest.useRealTimers();
});

// bun's fake timers advance synchronously, so let promise callbacks run between steps.
async function flush() {
  for (let i = 0; i < 10; i++) {
    await Promise.resolve();
  }
}

async function advance(ms: number) {
  await flush();
  for (let elapsed = 0; elapsed < ms; elapsed += 100) {
    jest.advanceTimersByTime(Math.min(100, ms - elapsed));
    await flush();
  }
}

function statuses(...states: JobState[]) {
  const calls = { count: 0 };
  const getStatus = async (): Promise<JobStatus> => {
    const state = states[Math.min(calls.count, states.length - 1)]!;
    calls.count += 1;
    return { state };
  };
  return { calls, getStatus };
}

describe("launchHelper", () => {
  test("opens sign and enrol links in a hidden iframe and removes it later", async () => {
    launchHelper(link(JOB));
    launchHelper(
      link("https://dash.example.org/v1/jobs/AbCdEfGhIjKlMnOpQrSt", "enrol")
    );
    expect(frames.map((frame) => [frame.hidden, frame.src])).toEqual([
      [true, link(JOB)],
      [
        true,
        link("https://dash.example.org/v1/jobs/AbCdEfGhIjKlMnOpQrSt", "enrol"),
      ],
    ]);
    await advance(5000);
    expect(frames.every((frame) => frame.removed)).toBe(true);
  });

  test.each([
    ["other scheme", `https://sign?job=${encodeURIComponent(JOB)}`],
    ["other action", link(JOB, "verify")],
    ["path", `keyseal://sign/x?job=${encodeURIComponent(JOB)}`],
    ["no job", "keyseal://sign"],
    ["two jobs", `${link(JOB)}&job=${encodeURIComponent(JOB)}`],
    ["http job", link(JOB.replace("https:", "http:"))],
    ["userinfo", link(JOB.replace("https://", "https://user@"))],
    ["query", link(`${JOB}?x=1`)],
    ["empty fragment", link(`${JOB}#`)],
    ["wrong path", link(`https://dash.example.org/jobs/${TOKEN}`)],
    [
      "base ending in slash",
      link(`https://dash.example.org//v1/jobs/${TOKEN}`),
    ],
    [
      "empty path segment",
      link(`https://dash.example.org/a//b/v1/jobs/${TOKEN}`),
    ],
    ["IPv4 host", link(`https://192.0.2.1/v1/jobs/${TOKEN}`)],
    ["IPv6 host", link(`https://[2001:db8::1]/v1/jobs/${TOKEN}`)],
    ["localhost over https", link(`https://localhost/v1/jobs/${TOKEN}`)],
    ["localhost subdomain", link(`https://app.localhost/v1/jobs/${TOKEN}`)],
    ["short token", link("https://dash.example.org/v1/jobs/short")],
    [
      "too long",
      link(`https://dash.example.org/${"a".repeat(2048)}/v1/jobs/${TOKEN}`),
    ],
  ])("rejects %s", (_, value) => {
    expect(() => launchHelper(value)).toThrow(TypeError);
    expect(frames).toHaveLength(0);
  });

  test("accepts local http job URLs only with allowInsecureOrigins", () => {
    const local = link(`http://localhost:8787/v1/jobs/${TOKEN}`);
    expect(() => launchHelper(local)).toThrow(TypeError);
    launchHelper(local, { allowInsecureOrigins: true });
    launchHelper(link(`http://127.0.0.1/v1/jobs/${TOKEN}`), {
      allowInsecureOrigins: true,
    });
    for (const job of [
      `http://dash.example.org/v1/jobs/${TOKEN}`,
      `http://10.0.0.1/v1/jobs/${TOKEN}`,
      `https://localhost/v1/jobs/${TOKEN}`,
      `https://127.0.0.1/v1/jobs/${TOKEN}`,
    ]) {
      expect(() =>
        launchHelper(link(job), { allowInsecureOrigins: true })
      ).toThrow(TypeError);
    }
    expect(frames).toHaveLength(2);
  });
});

describe("watchJob polling", () => {
  test("polls every interval and reports each change until completed", async () => {
    const { calls, getStatus } = statuses(
      "pending",
      "claimed",
      "claimed",
      "prepared",
      "completed"
    );
    const changes: JobState[] = [];
    const result = watchJob({
      getStatus,
      onChange: (status) => changes.push(status.state),
    });
    await advance(10_000);
    expect(await result).toEqual({ state: "completed" });
    expect(changes).toEqual(["pending", "claimed", "prepared", "completed"]);
    expect(calls.count).toBe(5);
  });

  test.each(["failed", "expired"] as const)("stops on %s", async (state) => {
    const { calls, getStatus } = statuses("claimed", state);
    const result = watchJob({ getStatus });
    await advance(2000);
    expect(await result).toEqual({ state });
    await advance(10_000);
    expect(calls.count).toBe(2);
  });

  test("calls onNotClaimed once at claimTimeoutMs and keeps polling", async () => {
    const { calls, getStatus } = statuses(
      "pending",
      "pending",
      "pending",
      "pending",
      "pending",
      "claimed",
      "completed"
    );
    let notClaimed = 0;
    const result = watchJob({ getStatus, onNotClaimed: () => notClaimed++ });
    await advance(4900);
    expect(notClaimed).toBe(0);
    await advance(100);
    expect(notClaimed).toBe(1);
    await advance(10_000);
    expect(await result).toEqual({ state: "completed" });
    expect(notClaimed).toBe(1);
    expect(calls.count).toBe(7);
  });

  test("skips onNotClaimed when the claim arrives in time", async () => {
    const { getStatus } = statuses("pending", "claimed");
    let notClaimed = 0;
    const result = watchJob({ getStatus, onNotClaimed: () => notClaimed++ });
    await advance(10_000);
    expect(notClaimed).toBe(0);
    await advance(15 * 60_000);
    await expect(result).rejects.toMatchObject({ name: "TimeoutError" });
  });

  test("rejects after timeoutMs and stops polling", async () => {
    const { calls, getStatus } = statuses("claimed");
    const result = watchJob({ getStatus, timeoutMs: 6000 });
    await advance(6000);
    await expect(result).rejects.toMatchObject({ name: "TimeoutError" });
    const count = calls.count;
    await advance(10_000);
    expect(calls.count).toBe(count);
  });

  test("rejects with the abort reason and stops polling", async () => {
    const { calls, getStatus } = statuses("claimed");
    const controller = new AbortController();
    const result = watchJob({ getStatus, signal: controller.signal });
    await advance(2000);
    controller.abort(new Error("left the page"));
    await expect(result).rejects.toThrow("left the page");
    await advance(10_000);
    expect(calls.count).toBe(2);
  });

  test("rejects at once for an aborted signal without polling", async () => {
    const { calls, getStatus } = statuses("claimed");
    const signal = AbortSignal.abort(new Error("gone"));
    await expect(watchJob({ getStatus, signal })).rejects.toThrow("gone");
    expect(calls.count).toBe(0);
  });

  test("rejects when onChange throws and stops polling", async () => {
    const { calls, getStatus } = statuses("pending", "claimed", "prepared");
    const result = watchJob({
      getStatus,
      onChange: () => {
        throw new Error("page gone");
      },
    });
    await expect(result).rejects.toThrow("page gone");
    await advance(10_000);
    expect(calls.count).toBe(1);
  });

  test("rejects with the getStatus error", async () => {
    const result = watchJob({
      getStatus: () => Promise.reject(new Error("offline")),
    });
    await expect(result).rejects.toThrow("offline");
  });
});

class FakeEventSource extends EventTarget {
  readyState = 1;
  closed = false;
  close() {
    this.closed = true;
    this.readyState = 2;
  }
  send(status: JobStatus) {
    this.dispatchEvent(
      new MessageEvent("state", { data: JSON.stringify(status) })
    );
  }
}

describe("watchJob with SSE", () => {
  test("follows state events without polling and closes the stream", async () => {
    const source = new FakeEventSource();
    let notClaimed = 0;
    const changes: JobStatus[] = [];
    const result = watchJob({
      eventSource: source as unknown as EventSource,
      onChange: (status) => changes.push(status),
      onNotClaimed: () => notClaimed++,
    });
    await advance(5000);
    expect(notClaimed).toBe(1);
    source.send({ state: "claimed" });
    source.send({ state: "failed", message: "Signing cancelled." });
    expect(await result).toEqual({
      state: "failed",
      message: "Signing cancelled.",
    });
    expect(changes.map((status) => status.state)).toEqual([
      "claimed",
      "failed",
    ]);
    expect(source.closed).toBe(true);
  });

  test("ignores reconnecting errors and rejects once the stream is closed", async () => {
    const source = new FakeEventSource();
    const result = watchJob({ eventSource: source as unknown as EventSource });
    source.dispatchEvent(new Event("error"));
    source.readyState = 2;
    source.dispatchEvent(new Event("error"));
    await expect(result).rejects.toThrow("closed");
  });
});

test("signWithHelper launches the helper and resolves with the final status", async () => {
  const { getStatus } = statuses("claimed", "completed");
  const result = signWithHelper({ link: link(JOB), getStatus });
  expect(frames).toHaveLength(1);
  await advance(2000);
  expect(await result).toEqual({ state: "completed" });
  await expect(
    signWithHelper({ link: "keyseal://sign", getStatus })
  ).rejects.toThrow(TypeError);
});

test.each([
  [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "macos",
  ],
  [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
    "windows",
  ],
  [
    "Mozilla/5.0 (X11; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0",
    "linux",
  ],
  [
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36",
    "unsupported",
  ],
  [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "unsupported",
  ],
  [
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "unsupported",
  ],
  ["curl/8.7.1", "unsupported"],
] as const)("helperDownloadFor(%s)", (userAgent, platform) => {
  expect(helperDownloadFor(userAgent)).toBe(platform);
});
