// Builds the signer guide's page into dist/: docs/signers.md rendered into
// page.html, with the guide's screenshots, the stylesheet and the icon.
// The guide stays the only copy of its text.

import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

const site = import.meta.dir;
const docs = join(site, "../docs");
const out = join(site, "dist");
// Relative links in the guide point into the repository on GitHub.
const repository = "https://github.com/somus/keyseal/blob/main/docs/";

const markdown = await Bun.file(join(docs, "signers.md")).text();
const sections: { id: string; title: string }[] = [];
let section: { id: string; title: string } | undefined;

const guide = await new HTMLRewriter()
  // The page's header names the guide instead.
  .on("h1", {
    element(heading) {
      heading.remove();
    },
  })
  .on("h2[id]", {
    element(heading) {
      section = { id: heading.getAttribute("id") ?? "", title: "" };
      sections.push(section);
      heading.onEndTag(() => {
        section = undefined;
      });
    },
    text(chunk) {
      if (section) {
        section.title += chunk.text;
      }
    },
  })
  .on("a[href]", {
    element(link) {
      const href = link.getAttribute("href") ?? "";
      if (!/^(#|[a-z]+:)/.test(href)) {
        link.setAttribute("href", new URL(href, repository).href);
      }
    },
  })
  .on("img", {
    element(image) {
      image.setAttribute("loading", "lazy");
      image.setAttribute("decoding", "async");
    },
  })
  // Wide tables scroll inside the column on a phone.
  .on("table", {
    element(table) {
      table.before('<div class="table">', { html: true });
      table.after("</div>", { html: true });
    },
  })
  .transform(
    new Response(Bun.markdown.html(markdown, { headings: { ids: true } }))
  )
  .text();

const escape = (text: string) =>
  text.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
const contents = sections
  .map(
    ({ id, title }) =>
      `<li><a href="#${escape(id)}">${escape(title.trim())}</a></li>`
  )
  .join("\n");

const template = await Bun.file(join(site, "page.html")).text();
const page = template
  .replace("<!-- contents -->", () => contents)
  .replace("<!-- guide -->", () => guide);

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });
await Bun.write(join(out, "index.html"), page);
await cp(join(site, "style.css"), join(out, "style.css"));
await cp(join(site, "../brand/keyseal-icon.svg"), join(out, "icon.svg"));
await cp(join(docs, "signers"), join(out, "signers"), { recursive: true });
console.log(`Built ${join(out, "index.html")}: ${sections.length} sections.`);
