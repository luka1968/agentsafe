# agentSAFE audit worker image.
# Secrets are NEVER baked in: all credentials arrive via environment
# variables at container start (GitHub Actions secrets -> docker run -e).

# NOTE: aderyn is intentionally NOT installed. Upstream (Cyfrin/aderyn)
# deleted every prebuilt release tarball (as of 2026-11-14 all tags ship
# only .sha256 files + source) and building it from source here is slow and
# fragile, so the analyzer is disabled at runtime (source.py defaults
# AGENTSAFE_ENABLE_ADERYN off). Audits run slither + mythril + heimdall.
# To re-enable: provision a working `aderyn` binary, set
# AGENTSAFE_ENABLE_ADERYN=1 at container start, and re-add its smoke check.

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
RUN slither --version && myth version && heimdall --version

ENTRYPOINT ["python", "scripts/run_audit.py"]
