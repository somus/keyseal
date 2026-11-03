# @keyseal/browser

Browser-side helper for pages that start a KeySeal job. It opens the `keyseal://` link without leaving the page, watches the job through the integrator's own status endpoint (polling by default, SSE optional), and tells the page when the helper hasn't picked up the job within about five seconds, so it can offer the download alongside the job's status while the job stays open.

The package has no runtime dependencies. It does not create jobs or talk to the job endpoint; your backend does that (see [`@keyseal/server`](../server/)).

The type declarations need TypeScript 4.7 or later. They are found through `exports` only, so `moduleResolution` must be `node16` or `nodenext`, or `bundler` from TypeScript 5.0.

## API

```ts
type JobState = "pending" | "claimed" | "prepared" | "completed" | "failed" | "expired";
interface JobStatus { state: JobState; message?: string }

launchHelper(link: string, options?: { allowInsecureOrigins?: boolean }): void;
watchJob(options: WatchOptions): Promise<JobStatus>;
signWithHelper(options: WatchOptions & { link: string; allowInsecureOrigins?: boolean }): Promise<JobStatus>;
helperDownloadFor(userAgent: string): "macos" | "windows" | "linux" | "unsupported";
```

`launchHelper` throws a `TypeError` unless the link is `keyseal://sign?job=...` or `keyseal://enrol?job=...` with an `https` job URL on a domain name (not an IP address or `localhost`) of the form `<base>/v1/jobs/<token>`, without empty path segments (spec sections 3 and 4). `allowInsecureOrigins` also accepts `http://localhost` and `http://127.0.0.1`, for use with the helper's `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` development override. The link opens in a hidden iframe, so an unregistered scheme cannot replace the page with an error page. Call it soon after the click that starts the job, since Chrome wants a recent user gesture before launching an app. A Content-Security-Policy must allow that frame: add `keyseal:` to `frame-src` (or to `child-src` or `default-src`, whichever applies), such as `frame-src 'self' keyseal:`. Otherwise the browser blocks the link without an error, and the helper never opens.

`WatchOptions`:

| Option | Default | Meaning |
| --- | --- | --- |
| `getStatus` | | `() => Promise<JobStatus>` that asks your backend for the job's state. Polled once at the start, then `intervalMs` after each answer. |
| `eventSource` | | An `EventSource` that sends `state` events whose `data` is a `JobStatus` as JSON. Use instead of `getStatus`. The watcher closes it when it stops. |
| `intervalMs` | `2000` | Delay between polls. |
| `claimTimeoutMs` | `5000` | How long the job may stay `pending` before `onNotClaimed` is called. |
| `timeoutMs` | `900000` | Give up after this long (15 minutes, the job TTL). |
| `signal` | | `AbortSignal` that stops watching. |
| `onChange` | | Called with each new status. |
| `onNotClaimed` | | Called once if the helper hasn't picked up the job by `claimTimeoutMs`. Watching continues, and `onChange` still reports the claim when it comes. |

`watchJob` resolves with the first `completed`, `failed` or `expired` status. It rejects with the abort reason on abort, with a `DOMException` named `TimeoutError` after `timeoutMs`, with any error `getStatus` throws, and with an `Error` if the event stream closes. Retry transient network errors inside `getStatus` if you want polling to survive them.

`onNotClaimed` means the helper hasn't picked up the job yet, not that it isn't installed. An installed helper can take longer than `claimTimeoutMs`: the browser may ask whether to open KeySeal, and the first time a signer meets your site the helper asks them to trust its origin before it fetches the job (spec section 5), which they may take a while to read. So render a "Didn't open? Download the helper" link next to the job's status, never a screen that only offers the install, and hide the link once `onChange` reports a state other than `pending`.

## Plain JavaScript

```js
import { helperDownloadFor, signWithHelper } from "@keyseal/browser";

// Fixed names on the latest release (docs/integrating.md, section 5).
const latest = "https://github.com/somus/keyseal/releases/latest/download";
const downloads = {
  macos: `${latest}/keyseal-macos-universal.dmg`,
  windows: `${latest}/keyseal-windows-x64.zip`, // unzip and run install.cmd
  linux: `${latest}/keyseal-linux-x64.AppImage`,
};

button.addEventListener("click", async () => {
  // Your backend creates the job and returns its id and keyseal:// link.
  const { jobId, link } = await fetch("/api/sign", { method: "POST" }).then((r) => r.json());
  const status = await signWithHelper({
    link,
    getStatus: () => fetch(`/api/sign/${jobId}`).then((r) => r.json()),
    onChange: ({ state }) => {
      statusText.textContent = state;
      // The helper has the job, so the fallback link is no longer needed.
      if (state !== "pending") notOpened.hidden = true;
    },
    // The helper may still be open on its trust prompt, so keep the status visible.
    onNotClaimed: () => {
      const platform = helperDownloadFor(navigator.userAgent);
      if (platform !== "unsupported") {
        downloadLink.href = downloads[platform];
        notOpened.hidden = false; // "Didn't open? Download the helper", beside the status
      }
    },
  });
  statusText.textContent = status.state === "completed" ? "Signed" : status.message ?? status.state;
});
```

Chrome's gesture check counts from the click, so keep job creation quick or create the job before the user clicks.

## React

The package ships no hook. This one starts a job, exposes the state and stops watching when the component unmounts. Show the download link while `notClaimed` is true and `status` is still `pending` (or not yet known), next to the status rather than in place of it.

```tsx
import { useEffect, useRef, useState } from "react";
import { signWithHelper, type JobStatus } from "@keyseal/browser";

export function useKeySeal(getStatus: (jobId: string) => Promise<JobStatus>) {
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [notClaimed, setNotClaimed] = useState(false);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  async function start(job: { jobId: string; link: string }) {
    controller.current?.abort();
    controller.current = new AbortController();
    setStatus(null);
    setNotClaimed(false);
    try {
      return await signWithHelper({
        link: job.link,
        getStatus: () => getStatus(job.jobId),
        signal: controller.current.signal,
        onChange: setStatus,
        onNotClaimed: () => setNotClaimed(true),
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        return null;
      }
      throw error;
    }
  }

  return { notClaimed, start, status };
}
```
