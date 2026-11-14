# The reference server with the workspace's @keyseal packages, built from the
# repository root (compose.yaml does that). Dockerfile.dockerignore picks
# the files it needs.
FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d
WORKDIR /app
COPY . .
RUN bun install --frozen-lockfile --production
WORKDIR /app/examples/reference-server
# The signed PDFs go to out/.
RUN mkdir out && chown bun out
USER bun
EXPOSE 8787
CMD ["bun", "run", "start"]
