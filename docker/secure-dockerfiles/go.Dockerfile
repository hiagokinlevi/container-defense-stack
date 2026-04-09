# =============================================================================
# Secure Go multi-stage Dockerfile
# Stage 1 (builder): compiles a fully static binary with CGO disabled.
# Stage 2 (runtime): distroless/static — no shell, no package manager, no OS
#                    utilities. Only the compiled binary is present.
# =============================================================================

# ---- Stage 1: builder -------------------------------------------------------
FROM golang:1.21-alpine AS builder

WORKDIR /src

# Copy go.mod and go.sum first so dependency downloads are cached separately
# from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build a fully static binary.
# CGO_DISABLED=0  — no C library linkage, enables fully static binary.
# GOOS=linux      — cross-compile target OS.
# -trimpath       — removes local build paths from the binary (reproducibility).
# -ldflags        — strip debug info and DWARF tables to reduce binary size.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/app \
    ./cmd/app

# ---- Stage 2: runtime -------------------------------------------------------
# distroless/static contains only CA certificates and timezone data.
# There is no shell, no package manager, and no writable OS directories.
FROM gcr.io/distroless/static:nonroot AS runtime

# The distroless nonroot image defines UID/GID 65532 as "nonroot".
# No USER instruction is needed — it is already the default in this image.
# Explicitly set it for clarity and to satisfy static analysis tools.
USER nonroot:nonroot

WORKDIR /app

# Copy only the compiled binary from the builder stage.
COPY --from=builder /out/app /app/app

ENTRYPOINT ["/app/app"]
