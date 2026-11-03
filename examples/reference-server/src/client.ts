/** The page's script, bundled by main.ts and served as /client.js. */
import {
  helperDownloadFor,
  signWithHelper,
  type JobStatus,
} from "@keyseal/browser";

/** What `GET /jobs/:id/status` returns. */
interface Status extends JobStatus {
  outputs: string[] | null;
}

// Fixed names on the latest release (docs/integrating.md, section 5).
const latest = "https://github.com/somus/keyseal/releases/latest/download";
const downloads = {
  linux: `${latest}/keyseal-linux-x64.AppImage`,
  macos: `${latest}/keyseal-macos-universal.dmg`,
  windows: `${latest}/keyseal-windows-x64.zip`,
};

function element<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

const form = element<HTMLFormElement>("form");
const notOpened = element("not-opened");

function show(id: string, text: string): void {
  element(id).textContent = text;
}

async function base64(file: File): Promise<string> {
  const url = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
  return url.slice(url.indexOf(",") + 1);
}

async function getStatus(id: string): Promise<Status> {
  const response = await fetch(`/jobs/${id}/status`);
  const status = (await response.json()) as Status;
  if (!response.ok) {
    throw new Error(status.message ?? `Status ${response.status}`);
  }
  return status;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const response = await fetch("/jobs", {
    body: JSON.stringify({
      documents: await Promise.all(
        (data.getAll("pdf") as File[]).map(async (file) => ({
          pdf: await base64(file),
          title: file.name,
        }))
      ),
      signer: data.get("signer"),
      title: data.get("title"),
    }),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
  const job = (await response.json()) as {
    id: string;
    link: string;
    message?: string;
  };
  element("job").hidden = false;
  notOpened.hidden = true;
  if (!response.ok) {
    show("state", "not created");
    show("detail", job.message ?? "");
    return;
  }
  element<HTMLAnchorElement>("link").href = job.link;
  show("state", "pending");
  show("detail", job.link);
  try {
    await signWithHelper({
      // Job URLs are http://localhost unless KEYSEAL_ORIGIN is https.
      allowInsecureOrigins: true,
      getStatus: () => getStatus(job.id),
      intervalMs: 1000,
      link: job.link,
      onChange: (change) => {
        const status = change as Status;
        show("state", status.state);
        if (status.message) show("detail", status.message);
        if (status.outputs) {
          show("detail", `Signed PDFs written to ${status.outputs.join(", ")}`);
        }
        // The helper has the job, so the download link is no longer needed.
        if (status.state !== "pending") notOpened.hidden = true;
      },
      // The helper may still be open on its trust prompt, so the status stays.
      onNotClaimed: () => {
        const platform = helperDownloadFor(navigator.userAgent);
        if (platform !== "unsupported") {
          element<HTMLAnchorElement>("download").href = downloads[platform];
          notOpened.hidden = false;
        }
      },
    });
  } catch (error) {
    notOpened.hidden = true;
    show("state", "unknown");
    show("detail", error instanceof Error ? error.message : String(error));
  }
});
