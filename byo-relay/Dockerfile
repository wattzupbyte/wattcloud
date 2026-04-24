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

# State directory — holds both the stats SQLite WAL and the share-relay
# ciphertext blobs + shares.sqlite3. Owned by appuser so the server can
# write to it. Pre-created and chowned here so that a fresh volume mount
# inherits the correct ownership (Docker seeds empty named volumes from
# the image's directory contents on first init).
RUN mkdir -p /var/lib/byo-relay/shares && chown -R 1000:1000 /var/lib/byo-relay

# Placeholder SPA (Phase 6 will replace this with the real frontend build)
RUN mkdir -p /app/dist
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/byo-relay /usr/local/bin/byo-relay
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/byo-admin /usr/local/bin/byo-admin
COPY dist/ /app/dist/

USER appuser
WORKDIR /app

ENV BIND_ADDR=0.0.0.0:8443
ENV SPA_DIR=/app/dist
ENV RUST_LOG=warn
ENV STATS_DB_PATH=/var/lib/byo-relay/stats.sqlite3
ENV SHARE_STORAGE_DIR=/var/lib/byo-relay/shares
ENV SHARE_DB_PATH=/var/lib/byo-relay/shares.sqlite3

# Persist state across container rebuilds. Operators should mount a named
# volume here (e.g. `-v wattcloud-data:/var/lib/byo-relay`); an anonymous
# volume is created by default if none is provided.
VOLUME /var/lib/byo-relay

EXPOSE 8443

# Liveness probe — byo-relay exposes /health (plain text "ok"). The reverse
# proxy (Caddy in the default deploy) terminates TLS upstream of the
# container, so this probe hits the relay on plain HTTP inside the network
# namespace.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:8443/health" 2>/dev/null | grep -q "ok" || exit 1

CMD ["byo-relay"]
