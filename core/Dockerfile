# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Use the official Go image to compile the Notary binary.
# Nothing from this stage reaches the final image except the compiled binary.
FROM golang:1.26-alpine AS builder

# Install git (needed by some Go modules) and ca-certificates (for HTTPS).
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy dependency manifests first — Docker caches this layer separately.
# go mod download only re-runs when go.mod or go.sum changes, not on code changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build the server binary.
# CGO_ENABLED=0  — pure Go binary, no C dependencies, works in scratch/alpine
# -trimpath      — removes local build paths from stack traces (security)
# -ldflags       — strips debug symbols (smaller binary)
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /bin/verilock-server \
    ./cmd/server

# ── Stage 2: Final image ──────────────────────────────────────────────────────
# Minimal Alpine — just enough to run the binary and SQLite.
# No build tools, no Go toolchain, no source code.
FROM alpine:3.19

# ca-certificates — needed for HTTPS calls to Base RPC endpoints
# tzdata          — needed for correct time zone handling in audit timestamps
RUN apk add --no-cache ca-certificates tzdata && \
    # Create a non-root user: verilock (uid 1001)
    # Running as root inside a container is unnecessary and increases attack surface.
    addgroup -g 1001 verilock && \
    adduser -u 1001 -G verilock -D -s /sbin/nologin verilock

# Copy the compiled binary from the builder stage.
COPY --from=builder /bin/verilock-server /usr/local/bin/verilock-server

# ── Runtime directory structure ───────────────────────────────────────────────
# These directories are created here so Docker knows they exist.
# Actual content comes from mounted volumes at runtime — nothing is baked in.
#
#   /data          ← audit.db, notary.key, agent.key (mounted from host)
#   /policies      ← policy.yaml (mounted from host)
#   /logs          ← optional log output
#
# SECURITY: Keys and policy files are NEVER baked into the image.
#           They are always mounted at runtime via docker-compose volumes.
RUN mkdir -p /data /policies /logs && \
    chown -R verilock:verilock /data /policies /logs

# Switch to non-root user for all subsequent operations including CMD.
USER verilock

# Expose the Notary HTTP port.
# The actual port is configured via SERVER_PORT in .env — this is documentation.
EXPOSE 8080

# Health check — Docker will mark the container unhealthy if this fails.
# Retries 3 times with 10s interval before marking unhealthy.
# start_period gives the server time to initialise before health checks begin.
HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=10s \
    --retries=3 \
    CMD wget -qO- http://localhost:8080/v1/health || exit 1

# Default entrypoint — run the Notary server.
# Config is loaded from environment variables (via .env mounted by docker-compose).
ENTRYPOINT ["/usr/local/bin/verilock-server"]