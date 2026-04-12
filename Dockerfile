# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.87-slim AS builder

# Install OpenSSL dev headers (needed by reqwest/hyper for TLS)
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first so dependency layer is cached separately from source
COPY Cargo.toml Cargo.lock* ./

# Dummy build to pre-compile all dependencies (cache layer)
RUN mkdir src && echo 'fn main(){}' > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Now copy real source and build
COPY src ./src
# Touch main.rs so cargo knows it changed
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# OpenSSL runtime + CA certs (for HTTPS outbound requests)
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/loadbalancer /app/loadbalancer

# LMDB data directory (mount a persistent volume here on Koyeb)
RUN mkdir -p /app/cdn.lmdb

EXPOSE 8000

CMD ["/app/loadbalancer"]
