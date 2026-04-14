# Secure Dockerfile Baseline Template
#
# This template demonstrates container hardening best practices:
# - Minimal base image
# - Explicit file copying
# - Non-root execution
# - No package manager cache
# - Healthcheck for runtime monitoring
# - Reduced attack surface

############################
# Stage 1 — Build (optional)
############################
# Use a minimal builder image. Alpine keeps the build stage small
# while still providing common build tooling.
FROM python:3.11-alpine AS builder

# Prevent Python from writing .pyc files and enable unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /build

# Copy only dependency files first to improve build cache behavior
# and avoid copying unnecessary project files early.
COPY requirements.txt ./

# Install dependencies without leaving package manager cache behind
# to reduce final image size and attack surface.
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy application source explicitly
COPY app/ ./app


############################
# Stage 2 — Runtime Image
############################
# Use a minimal runtime base image. Alpine is small and widely supported.
# Distroless images can be used instead when shell access is not required.
FROM alpine:3.19

# Create a dedicated non-root user to prevent container breakout
# impact if the application is compromised.
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy only the built dependencies and application code from builder stage
# This avoids including build tools in the final runtime image.
COPY --from=builder /install /usr/local
COPY --from=builder /build/app ./app

# Ensure files are owned by the non-root runtime user
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Expose only the application port (document intent)
EXPOSE 8080

# HEALTHCHECK allows container orchestrators to detect unhealthy containers
# and restart them automatically.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

# Run the application
CMD ["python", "app/main.py"]
