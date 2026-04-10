# ── Stage 1: build the oxigate binary ────────────────────────────────────────
FROM rust:1.94-slim-bookworm AS builder

# Install build dependencies (pkg-config + OpenSSL dev headers)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the entire workspace (context is the repo root)
COPY . .

RUN cargo build --release -p oxigate-app

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM debian:12-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/oxigate /usr/local/bin/oxigate

EXPOSE 8080 8443

ENTRYPOINT ["oxigate"]
CMD ["--config", "/etc/oxigate/gateway.yaml"]
