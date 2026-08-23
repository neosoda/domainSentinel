# ── Build stage ─────────────────────────────────────────────────────────────
FROM golang:1.23-bookworm AS builder

WORKDIR /build

# Install build dependencies (git for go modules, gcc for CGO sqlite3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" \
    -o domainsentinel .

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="DomainSentinel"
LABEL org.opencontainers.image.description="Domain & DNS inventory & monitoring tool"
LABEL org.opencontainers.image.source="https://github.com/techsentinel/domainsentinel"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata openssl curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (Debian adduser syntax)
# GID 984 = host docker group (socket owner) — we add the user to this group
# at build time so the container can read the docker socket without
# needing --group-add 984 at runtime (which Coolify strips).
RUN addgroup --system --gid 1000 domainsentinel && \
    addgroup --system --gid 984 docker && \
    adduser --system --uid 1000 --ingroup domainsentinel --disabled-login --disabled-password domainsentinel && \
    usermod -aG docker domainsentinel

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/domainsentinel .

# Copy web assets
COPY web/ /app/web/

# Create data/config directories
RUN mkdir -p /data /config && chown -R domainsentinel:domainsentinel /app /data /config

# Switch to non-root user
USER domainsentinel

# Read-only filesystem (data/config are mounted)
VOLUME ["/data", "/config"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:3000/health || exit 1

ENTRYPOINT ["/app/domainsentinel"]
