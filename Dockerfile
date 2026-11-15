# agentSAFE audit worker image.
# Secrets are NEVER baked in: all credentials arrive via environment
# variables at container start (GitHub Actions secrets -> docker run -e).

# --- Stage 1: build aderyn from the pinned source tag -----------------------
# Upstream deleted every prebuilt release tarball (as of 2026-11-14 all
# Cyfrin/aderyn tags ship only .sha256 files + source), which broke the
# image build that used to download aderyn-x86_64-unknown-linux-gnu.tar.xz.
# Building from the tag's committed Cargo.lock keeps version 0.6.8 and its
# verified CLI contract stable. rust:1.85-slim ships gcc (needed by the cc
# crates) and covers edition-2024 (rustc >= 1.85).
FROM rust:1.85-slim AS aderyn-builder
# The workspace profile uses fat LTO (lto=true, codegen-units=1); that
# triples compile time for no audit-runtime benefit - override via env.
ENV CARGO_PROFILE_RELEASE_LTO=off \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_NET_RETRY=10
RUN cargo install --locked \
      --git https://github.com/Cyfrin/aderyn --tag aderyn-v0.6.8 \
      aderyn \
    && rm -rf "$CARGO_HOME/git" "$CARGO_HOME/registry" \
    && aderyn --version

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential curl xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts

# Project + pinned analysis tools (same pins as .github/workflows/audit.yml).
# slither and mythril have conflicting shared-dependency pins; installing them
# in ONE resolver run fails with ResolutionImpossible. Install sequentially
# (last install wins on shared deps) and gate on agentsafe still importing.
RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir slither-analyzer==0.10.4 \
    && pip install --no-cache-dir mythril==0.24.3 \
    && pip install --no-cache-dir solc-select==1.2.0 \
    && pip install --no-cache-dir "setuptools<81" \
    && python -c "import agentsafe.server" \
    && solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.19 0.8.20 0.8.24 \
    && solc-select use 0.8.19

# Aderyn binary from the source-build stage (see stage 1 rationale above).
COPY --from=aderyn-builder /usr/local/cargo/bin/aderyn /usr/local/bin/aderyn

# Heimdall (pinned release, computed checksum; re-verify when bumping).
RUN set -eu \
    && curl -fsSL --retry 3 -o /usr/local/bin/heimdall \
        "https://github.com/Jon-Becker/heimdall-rs/releases/download/0.9.3/heimdall-linux-amd64" \
    && echo "8d58c97f56d584d5d0737d0d0895fc8c68b7b8b2b680f2a7842245789f0b4868  /usr/local/bin/heimdall" | sha256sum -c - \
    && chmod +x /usr/local/bin/heimdall

# Ephemeral container: no durable writable storage is guaranteed.
ENV TASK_STORE=memory \
    TASK_DB_PATH=/tmp/tasks.db

# Smoke-gate the toolchain at build time; a broken image must fail HERE.
RUN slither --version && myth version && aderyn --version && heimdall --version

ENTRYPOINT ["python", "scripts/run_audit.py"]
