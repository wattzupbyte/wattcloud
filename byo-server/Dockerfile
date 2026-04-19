# Build stage: musl static linking for a fully static binary
FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 appuser

# Stats database directory — owned by appuser so the server can write to it.
# The directory is pre-created here so that the named volume mount inherits the
# correct ownership on first init (Docker copies image dir contents to fresh volumes).
RUN mkdir -p /var/lib/byo-server && chown 1000:1000 /var/lib/byo-server

# Placeholder SPA (Phase 6 will replace this with the real frontend build)
RUN mkdir -p /app/dist
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/byo-server /usr/local/bin/byo-server
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/byo-admin /usr/local/bin/byo-admin
COPY dist/ /app/dist/

USER appuser
WORKDIR /app

ENV BIND_ADDR=0.0.0.0:8443
ENV SPA_DIR=/app/dist
ENV RUST_LOG=warn
ENV STATS_DB_PATH=/var/lib/byo-server/stats.sqlite3

EXPOSE 8443

# Liveness probe — byo-server exposes /health (plain text "ok").
# --no-check-certificate: Traefik terminates TLS; byo-server may use self-signed or plain HTTP.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- --no-check-certificate "http://127.0.0.1:8443/health" 2>/dev/null | grep -q "ok" || exit 1

CMD ["byo-server"]
