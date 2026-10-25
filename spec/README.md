# spec

Version 1 of the KeySeal protocol, implemented by the helper and `@keyseal/server`. It stays a draft until the first helper release.

- [protocol-v1.md](protocol-v1.md) is the normative specification: the `keyseal://` link, origin and trust rules, the `/.well-known/keyseal.json` manifest, the two-round job endpoint and the document download, SignedAttributes validation, algorithms, helper UI requirements, the helper's update manifest and security considerations.
- [openapi.yaml](openapi.yaml) is its OpenAPI 3.1 companion for the manifest and the job endpoint, with a JSON Schema for every body under the names the Markdown uses (`Manifest`, `JobDescription`, `CertificateSubmission`, `PreparedSignature` and so on). The Markdown wins where the two disagree.
- [decisions.md](decisions.md) lists the details the design left open and how version 1 settled them.

Check the OpenAPI file with `npx -y @redocly/cli@latest lint spec/openapi.yaml`.
