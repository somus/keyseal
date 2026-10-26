# Releasing the signing service image

The signing service is versioned and released on its own. Pushing a
`service-vX.Y.Z` tag runs `.github/workflows/service.yml`, which checks that
the tag is on main and matches `version` in `service/pyproject.toml`, runs the
service tests, builds `service/Dockerfile` for linux/amd64 and linux/arm64,
and pushes `ghcr.io/somus/keyseal-service` tagged `X.Y.Z` and `X.Y`, with a
build provenance attestation. No `latest` tag is pushed.

## Steps

1. Bump `version` in `service/pyproject.toml`, run `uv lock` in `service/`,
   and merge the change in a pull request.
2. Tag the merge commit and push the tag:

   ```sh
   git tag service-v0.2.0 && git push origin service-v0.2.0
   ```

3. Check the run in Actions. Its summary lists the image digest; check the
   attestation against it:

   ```sh
   gh attestation verify oci://ghcr.io/somus/keyseal-service@sha256:<digest> --repo somus/keyseal
   ```

Integrators who want an image that can't move pin the digest,
`ghcr.io/somus/keyseal-service@sha256:<digest>`, rather than a tag.

## One-time setup

The workflow pushes with the workflow's `GITHUB_TOKEN`, so no registry token
is kept in GitHub. The first push creates the package as private and links it
to the repository through the image's `org.opencontainers.image.source`
label. After that run, open the package's settings
(github.com/users/somus/packages/container/keyseal-service/settings) and set
its visibility to public, so integrators can pull it without logging in.
