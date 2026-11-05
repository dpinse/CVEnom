# syntax=docker/dockerfile:1
# Build context: backend/   (docker build -t cvenom-backend backend/)

FROM python:3.14-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
# Dependencies first: only hash-pinned artifacts are accepted.
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
# The app itself (all of its dependencies are already installed and pinned).
# Build backend is hash-pinned too, so the build uses no unhashed downloads.
COPY build-constraints.lock .
RUN pip install --no-cache-dir --require-hashes -r build-constraints.lock
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation .

FROM python:3.14-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY alembic.ini ./
COPY migrations ./migrations
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Writable only where needed: the GeoIP volume mount point (worker).
RUN mkdir -p /data/geoip \
    && chown -R 10001:10001 /data \
    && chmod 0755 /usr/local/bin/docker-entrypoint.sh
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["sh", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["api"]
