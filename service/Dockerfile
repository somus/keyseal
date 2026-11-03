# KeySeal signing service (pyHanko). Keep it on a private network.
FROM python:3.15-slim@sha256:8c13a3f37a6a5b71498228e902c4b9f51c1f7900d49fabf71f9a650c6120e0d0 AS base
COPY --from=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY keyseal_service ./keyseal_service
RUN uv sync --frozen --no-dev --no-editable
RUN useradd --system --uid 10001 signing && chown -R signing /app
USER signing
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["/app/.venv/bin/python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/health').status == 200 else 1)"]
CMD ["/app/.venv/bin/uvicorn", "keyseal_service.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
