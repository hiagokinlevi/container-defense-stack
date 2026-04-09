# Container Hardening Guide

This guide covers the practical steps to reduce the attack surface of container
images and the processes that run inside them. It applies to any OCI-compatible
container built and deployed to Kubernetes.

---

## 1. Multi-Stage Builds

A multi-stage build separates compilation from the final runtime image. The build
toolchain, source code, and intermediate artifacts never appear in the image that
gets deployed or shipped.

### Python example

```dockerfile
# Stage 1: install dependencies in a build-only layer.
FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: minimal runtime — no pip, no gcc, no build cache.
FROM python:3.11-slim AS runtime
WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=10001:10001 . .
USER 10001
HEALTHCHECK CMD python -c "import sys; sys.exit(0)"
CMD ["python", "-m", "app"]
```

### Go example (scratch / distroless)

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app

# gcr.io/distroless/static contains only CA certs and timezone data — no shell.
FROM gcr.io/distroless/static:nonroot AS runtime
COPY --from=builder /out/app /app/app
USER nonroot:nonroot
ENTRYPOINT ["/app/app"]
```

**Why distroless or scratch?**

- No shell means an attacker cannot run interactive commands even if they gain
  code execution.
- No package manager means there is nothing to install additional tooling with.
- The image is typically 5–15 MB instead of 200–900 MB for a full OS base.

---

## 2. Non-Root Users

Containers run as root by default unless a `USER` instruction is present. If a
process running as root inside a container escapes the container namespace, it
has root on the underlying node.

### Dockerfile

```dockerfile
# Create a dedicated non-root group and user with fixed IDs.
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

USER 10001
```

### Kubernetes enforcement

Set `runAsNonRoot: true` at the pod level. The kubelet will refuse to start the
container if the image's default user is UID 0:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
```

### Numeric vs. named users

Use the numeric UID (e.g., `USER 10001`) rather than a username. Minimal images
often have no `/etc/passwd`, so named users may not resolve correctly.

---

## 3. Read-Only Root Filesystem

A writable root filesystem allows an attacker to modify binaries, drop scripts,
or alter configuration files at runtime. Setting it to read-only forces all
writes to explicitly mounted volumes.

### Kubernetes

```yaml
securityContext:
  readOnlyRootFilesystem: true

volumeMounts:
  - name: tmp
    mountPath: /tmp     # Provide a writable scratch area if the app needs one.
  - name: cache
    mountPath: /var/cache/app

volumes:
  - name: tmp
    emptyDir: {}
  - name: cache
    emptyDir: {}
```

### Application changes required

- Redirect log output to stdout/stderr (Kubernetes captures this automatically).
- Move any file writes (PID files, lock files, temp files) to an emptyDir mount.
- Check startup scripts for writes to `/etc`, `/var`, or other root paths.

---

## 4. Removing Unnecessary Capabilities

Linux capabilities grant fine-grained kernel privileges. Dropping all of them and
adding back only what the application requires follows the principle of least
privilege at the kernel level.

```yaml
securityContext:
  capabilities:
    drop:
      - ALL         # Remove every capability from the default set.
    add:
      - NET_BIND_SERVICE  # Re-add only if the app must bind to ports < 1024.
```

### Common capabilities and their risks

| Capability | Risk |
|---|---|
| `CAP_SYS_ADMIN` | Near-root; enables mount, ptrace, namespace manipulation |
| `CAP_NET_RAW` | Enables raw socket sniffing and ARP spoofing |
| `CAP_SYS_PTRACE` | Enables debugging and reading other processes' memory |
| `CAP_DAC_OVERRIDE` | Bypasses file permission checks |

For most web services and batch workers, `drop: [ALL]` with no additions is the
correct posture. Use `capsh --print` inside a test container to see which
capabilities your application actually exercises.

---

## 5. Image Scanning Workflow

Static analysis of container images identifies known CVEs before the image is
deployed. Integrate scanning into CI so vulnerabilities are caught at build time.

### Recommended toolchain

| Tool | Use case |
|---|---|
| **Trivy** (Aqua Security) | Fast CVE scanner for OS packages and language dependencies |
| **Grype** (Anchore) | Comprehensive scanner with SBOM generation |
| **Syft** | Software Bill of Materials (SBOM) generation |
| **Docker Scout** | Native Docker Desktop / Docker Hub integration |

### Example: Trivy in GitHub Actions

```yaml
- name: Scan image with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: "ghcr.io/myorg/myapp:${{ github.sha }}"
    format: "table"
    exit-code: "1"            # Fail the pipeline on HIGH/CRITICAL findings.
    ignore-unfixed: true      # Skip CVEs with no available fix.
    severity: "HIGH,CRITICAL"
```

### SBOM generation

An SBOM documents every package in the image, enabling rapid impact assessment
when a new CVE is published:

```bash
# Generate SBOM with Syft
syft ghcr.io/myorg/myapp:1.0.0 -o cyclonedx-json > sbom.json

# Scan the SBOM with Grype (faster than re-pulling the image)
grype sbom:sbom.json
```

### Build-time secrets

Never use `ENV` or `ARG` for secrets — they are baked into the image layer history.

```dockerfile
# Correct: use BuildKit's --secret flag (secret never appears in layers).
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm install
```

```bash
docker buildx build --secret id=npmrc,src=$HOME/.npmrc .
```

---

## Summary Checklist

- [ ] Multi-stage build with minimal runtime base (slim, distroless, or scratch)
- [ ] `USER <non-zero-uid>` instruction before CMD/ENTRYPOINT
- [ ] `readOnlyRootFilesystem: true` with emptyDir mounts for writable paths
- [ ] `capabilities.drop: [ALL]` in container securityContext
- [ ] No secrets in `ENV` or `ARG` — use `--secret` or runtime injection
- [ ] Image pinned to a specific digest or semver tag, never `:latest`
- [ ] Trivy or Grype scan in CI pipeline with exit-code: 1 on HIGH/CRITICAL
- [ ] SBOM generated and stored alongside each release artifact
