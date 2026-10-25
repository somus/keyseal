/** Job states from section 9.1 of the protocol spec. */
export type JobState =
  | "pending"
  | "claimed"
  | "prepared"
  | "completed"
  | "failed"
  | "expired";

export interface JobStatus {
  state: JobState;
  message?: string;
}

export type HelperPlatform = "macos" | "windows" | "linux" | "unsupported";

export interface LaunchOptions {
  /** Accept `http://localhost` and `http://127.0.0.1` job URLs, matching the helper's development override (spec section 4.4). */
  allowInsecureOrigins?: boolean;
}

/** Either poll the integrator's status endpoint or consume `state` events from it. */
export type JobSource =
  | { getStatus: () => Promise<JobStatus>; eventSource?: undefined }
  | { eventSource: EventSource; getStatus?: undefined };

export type WatchOptions = JobSource & {
  intervalMs?: number;
  claimTimeoutMs?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  onChange?: (status: JobStatus) => void;
  /** Called once if the job is still pending after `claimTimeoutMs`. Watching continues. */
  onNotClaimed?: () => void;
};

const TERMINAL = new Set<JobState>(["completed", "failed", "expired"]);
const JOB_PATH = /^(?:\/[^/]+)*\/v1\/jobs\/[A-Za-z0-9_-]{20,128}$/;
const INSECURE_HOSTS = new Set(["localhost", "127.0.0.1"]);

// URL.parse needs Safari 18, so keep the try for older macOS installs.
function parseUrl(value: string): URL | undefined {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

/** Throws a TypeError unless `link` is a `keyseal://sign` or `keyseal://enrol` link whose job URL follows spec section 3. */
function assertHelperLink(link: string, options: LaunchOptions = {}): void {
  const fail = (reason: string): never => {
    throw new TypeError(`Invalid KeySeal link: ${reason}.`);
  };
  if (link.length > 2048) {
    fail("longer than 2048 characters");
  }
  const url = parseUrl(link) ?? fail("not a URL");
  if (
    url.protocol !== "keyseal:" ||
    (url.host !== "sign" && url.host !== "enrol")
  ) {
    fail("expected keyseal://sign or keyseal://enrol");
  }
  if (url.pathname !== "" && url.pathname !== "/") {
    fail("unexpected path");
  }
  const jobs = url.searchParams.getAll("job");
  if (jobs.length !== 1) {
    fail("expected exactly one job parameter");
  }
  const raw = jobs[0]!;
  const job = parseUrl(raw) ?? fail("job is not a URL");
  const insecure =
    options.allowInsecureOrigins === true &&
    job.protocol === "http:" &&
    INSECURE_HOSTS.has(job.hostname);
  if (!insecure && job.protocol !== "https:") {
    fail("job URL must use https");
  }
  // WHATWG URL serialises every IP host as dotted decimal or bracketed IPv6.
  const host = job.hostname;
  if (
    !insecure &&
    (host.startsWith("[") ||
      /^[0-9.]+$/.test(host) ||
      host === "localhost" ||
      host.endsWith(".localhost"))
  ) {
    fail("job URL host must be a domain name, not an IP address or localhost");
  }
  if (job.username || job.password || /[?#]/.test(raw)) {
    fail("job URL must not carry userinfo, query or fragment");
  }
  if (!JOB_PATH.test(job.pathname)) {
    fail("job URL path must end in /v1/jobs/<token>");
  }
}

/**
 * Opens a `keyseal://` link without navigating the page away.
 *
 * The link is loaded in a hidden, unsandboxed iframe rather than through
 * `window.location`. Chrome, Edge and Safari hand an iframe's custom-scheme
 * navigation to the registered app the same way as a top-level one. When no
 * app is registered, Firefox and Safari replace the document that navigated
 * with an error page; in an iframe that page is invisible, while a top-level
 * navigation would leave the user on it. A top-level navigation can also
 * cancel requests the page has in flight. Chrome asks for a recent user
 * gesture before launching an external app, so call this soon after the
 * click that starts the job. The iframe is removed after a few seconds.
 */
export function launchHelper(link: string, options?: LaunchOptions): void {
  assertHelperLink(link, options);
  const frame = document.createElement("iframe");
  frame.hidden = true;
  frame.src = link;
  document.body.append(frame);
  setTimeout(() => frame.remove(), 5000);
}

/**
 * Follows a job until it reaches a terminal state, then resolves with that status.
 * Rejects with the abort reason on abort, with a `TimeoutError` DOMException after
 * `timeoutMs`, and with whatever `getStatus` throws.
 */
export function watchJob(options: WatchOptions): Promise<JobStatus> {
  const {
    intervalMs = 2000,
    claimTimeoutMs = 5000,
    timeoutMs = 15 * 60_000,
    signal,
    onChange,
    onNotClaimed,
  } = options;
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    let last: JobStatus | undefined;
    let done = false;
    let pollTimer: ReturnType<typeof setTimeout> | undefined;
    const finish = (settle: () => void) => {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(claimTimer);
      clearTimeout(deadline);
      clearTimeout(pollTimer);
      signal?.removeEventListener("abort", abort);
      options.eventSource?.close();
      settle();
    };
    const fail = (error: unknown) => finish(() => reject(error));
    const abort = () => fail(signal?.reason);
    const update = (status: JobStatus) => {
      if (done) {
        return;
      }
      if (status.state !== last?.state || status.message !== last?.message) {
        last = status;
        onChange?.(status);
      }
      if (TERMINAL.has(status.state)) {
        finish(() => resolve(status));
      }
    };

    signal?.addEventListener("abort", abort);
    const claimTimer = setTimeout(() => {
      if (last === undefined || last.state === "pending") {
        onNotClaimed?.();
      }
    }, claimTimeoutMs);
    const deadline = setTimeout(
      () =>
        fail(
          new DOMException(
            "The helper did not finish the job in time.",
            "TimeoutError"
          )
        ),
      timeoutMs
    );

    if (options.eventSource) {
      const { eventSource } = options;
      eventSource.addEventListener("state", (event) => {
        try {
          update(JSON.parse((event as MessageEvent<string>).data) as JobStatus);
        } catch (error) {
          fail(error);
        }
      });
      // EventSource reconnects on its own; only a closed stream is final.
      eventSource.addEventListener("error", () => {
        if (eventSource.readyState === 2) {
          fail(new Error("The job event stream closed."));
        }
      });
      return;
    }
    const { getStatus } = options;
    const poll = () => {
      // A throwing onChange ends the watch like a failed poll would.
      getStatus()
        .then((status) => {
          update(status);
          if (!done) {
            pollTimer = setTimeout(poll, intervalMs);
          }
        })
        .catch(fail);
    };
    poll();
  });
}

/** Launches the helper for `link` and watches the job to its final status. */
export async function signWithHelper(
  options: WatchOptions & LaunchOptions & { link: string }
): Promise<JobStatus> {
  launchHelper(options.link, options);
  return watchJob(options);
}

/** Which helper build suits the browser's platform, for picking a download link. */
export function helperDownloadFor(userAgent: string): HelperPlatform {
  if (/Android|iPhone|iPad|iPod|CrOS/.test(userAgent)) {
    return "unsupported";
  }
  if (/Windows NT/.test(userAgent)) {
    return "windows";
  }
  if (/Macintosh|Mac OS X/.test(userAgent)) {
    return "macos";
  }
  if (/Linux|X11/.test(userAgent)) {
    return "linux";
  }
  return "unsupported";
}
