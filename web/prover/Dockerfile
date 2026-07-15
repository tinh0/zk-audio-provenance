# HyperVerITAS Prover Docker Image
# Multi-stage build: compile Rust, then create slim runtime image
#
# Build: docker build -t hyperveritas-prover -f web/prover/Dockerfile .
# (Run from the zk-audio-provenance repo root, which contains hyperveritas-audio/, web/, etc.)

# ============================================================
# Stage 1: Build all Rust example binaries
# ============================================================
FROM rust:nightly-bookworm AS builder

WORKDIR /build

# Copy dependency source trees first (for better caching); destination stays
# flat so hyperveritas_impl's relative path deps (../hyperplonk) still resolve
COPY hyperveritas-audio/hyperplonk/ hyperplonk/
COPY hyperveritas-audio/plonkish_basefold/ plonkish_basefold/
COPY hyperveritas-audio/hyperveritas_impl/ hyperveritas_impl/

WORKDIR /build/hyperveritas_impl

# Build all examples in release mode
RUN cargo build --release --examples

# ============================================================
# Stage 2: Slim runtime image
# ============================================================
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      unzip \
      jq && \
    rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws/

# Copy all HyperVerITAS example binaries
COPY --from=builder /build/hyperveritas_impl/target/release/examples/hv_* /usr/local/bin/

# Create working directories
RUN mkdir -p /work/images /work/audio

WORKDIR /work

# Copy entrypoint
COPY web/prover/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
