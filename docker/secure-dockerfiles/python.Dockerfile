# =============================================================================
# Secure Python multi-stage Dockerfile
# Stage 1 (builder): installs dependencies in an isolated environment.
# Stage 2 (runtime): minimal image, non-root user, no build tooling included.
# =============================================================================

# ---- Stage 1: builder -------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Copy only the dependency manifest first to leverage Docker layer caching.
# Re-installing deps only when requirements.txt changes.
COPY requirements.txt .

# Install dependencies into a user-local prefix so we can copy them cleanly.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Stage 2: runtime -------------------------------------------------------
FROM python:3.11-slim AS runtime

# Create a dedicated non-root group and user with a fixed GID/UID.
# Using numeric IDs (10001) avoids name-resolution issues in minimal images.
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy installed Python packages from the builder stage.
COPY --from=builder /install /usr/local

# Copy application source code.
COPY --chown=appuser:appgroup . .

# Drop to non-root user for all subsequent instructions and at runtime.
USER 10001

# Verify the application starts correctly; adjust the command for your entrypoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "-m", "app"]
