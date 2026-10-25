/** The one page: upload PDFs, open the keyseal:// link, watch the job. */
export const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KeySeal reference server</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 36rem; margin: 3rem auto; padding: 0 1rem; }
  label { display: block; margin-top: 1rem; }
  input { display: block; width: 100%; margin-top: 0.25rem; }
  button { margin-top: 1.5rem; }
  #job { margin-top: 2rem; }
</style>
</head>
<body>
<h1>Sign PDFs</h1>
<form id="form">
  <label>PDFs, up to 20 signed together <input name="pdf" type="file" accept="application/pdf" multiple required></label>
  <label>Title <input name="title" value="Test document" required maxlength="200"></label>
  <label>Signer <input name="signer" value="Test Signer" required maxlength="200"></label>
  <button type="submit">Create signing job</button>
</form>
<div id="job" hidden>
  <p><a id="link">Open in the KeySeal helper</a></p>
  <p>State: <strong id="state">pending</strong></p>
  <p id="detail"></p>
</div>
<script>
const form = document.getElementById("form");
const show = (id, text) => { document.getElementById(id).textContent = text; };

async function base64(file) {
  const url = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
  return url.slice(url.indexOf(",") + 1);
}

async function watch(id) {
  for (;;) {
    const response = await fetch("/jobs/" + id + "/status");
    const status = await response.json();
    show("state", status.state ?? "unknown");
    if (status.message) show("detail", status.message);
    if (status.outputs) show("detail", "Signed PDFs written to " + status.outputs.join(", "));
    if (!["pending", "claimed", "prepared"].includes(status.state)) return;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const response = await fetch("/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      documents: await Promise.all(
        data.getAll("pdf").map(async (file) => ({ pdf: await base64(file), title: file.name }))
      ),
      signer: data.get("signer"),
      title: data.get("title"),
    }),
  });
  const job = await response.json();
  document.getElementById("job").hidden = false;
  if (!response.ok) {
    show("state", "not created");
    show("detail", job.message);
    return;
  }
  const link = document.getElementById("link");
  link.href = job.link;
  show("detail", job.link);
  location.href = job.link;
  watch(job.id);
});
</script>
</body>
</html>
`;
