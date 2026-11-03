/** The one page: upload PDFs, open the keyseal:// link, watch the job. Its script is client.ts. */
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
<script type="module" src="/client.js"></script>
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
  <p id="not-opened" hidden>Didn't open? <a id="download">Download the helper</a></p>
  <p id="detail"></p>
</div>
</body>
</html>
`;
