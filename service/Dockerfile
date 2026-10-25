# KeySeal signing service (pyHanko). Keep it on a private network.
FROM python:3.15-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.13 /uv /usr/local/bin/uv
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
