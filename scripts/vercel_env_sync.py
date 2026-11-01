"""Bulk-sync environment variables from .env to a Vercel project via the
REST API (no manual panel clicking).

Usage:
    python scripts/vercel_env_sync.py --token <VERCEL_TOKEN> --project <prj_xxx> [--team <team_xxx>]

Behaviour (idempotent):
  - Reads keys from .env (local, gitignored) filtered by --include prefixes.
  - For each key: lists existing project env vars, deletes stale ones that
    are NOT in the .env set (so removed local vars don't linger), then
    creates/updates every .env var with type=plain for target production.
  - Never prints values; only key names and a masked status.

Env-var list targeted (the runtime-required set for agentSAFE on Vercel):
  INFURA_ETH_ENDPOINT, ETHERSCAN_API_KEY, LLM_PROVIDERS_JSON, LLM_GLOBAL_RPM,
  LLM_MAX_CALLS_PER_AUDIT, LLM_MAX_RETRIES_PER_CALL, LLM_REQUEST_TIMEOUT_SECONDS,
  LLM_MAX_OUTPUT_TOKENS, GITHUB_TOKEN, GITHUB_REPO, GITHUB_WORKFLOW_FILE,
  GITHUB_REF, GITHUB_API_TIMEOUT_SECONDS, GITHUB_POLL_INTERVAL_SECONDS,
  AUDIT_TIMEOUT_SECONDS, MAX_CONCURRENT_AUDITS, ARTIFACT_RETENTION_DAYS,
  TASK_STORE, REDIS_URL, PAYMENTS_ENABLED, X402_NETWORK, X402_PAY_TO,
  X402_SDK_VERSION, X402_FACILITATOR_URL, X402_PRICE, X402_REST_PRICE,
  X402_ASSET, X402_MAX_TIMEOUT_SECONDS, X402_ALLOW_MAINNET, LOG_LEVEL,
  HTTP_RATE_LIMIT_PER_MINUTE, HTTP_MAX_BODY_BYTES, METRICS_JSONL_PATH,
  CORS_ORIGINS, NVIDIA_API_KEY, NVIDIA_EMBED_MODEL, NVIDIA_BASE_URL,
  EMBED_DIM, KB_VECTOR_DIM, KB_STORAGE, NEON_DATABASE_URL
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

API = "https://api.vercel.com"

# All runtime env vars agentSAFE may need on Vercel (production target).
# Values come from the local .env; only keys present there are synced.
INCLUDE_PREFIXES = (
    "INFURA_",
    "ETHERSCAN_",
    "LLM_",
    "GITHUB_",
    "AUDIT_",
    "MAX_CONCURRENT",
    "ARTIFACT_",
    "TASK_",
    "REDIS_",
    "PAYMENTS_",
    "X402_",
    "LOG_LEVEL",
    "HTTP_",
    "METRICS_",
    "CORS_",
    "NVIDIA_",
    "EMBED_",
    "KB_",
    "NEON_",
)


def _request(
    token: str, method: str, path: str, body: dict | None = None, team: str = ""
) -> tuple[int, dict]:
    url = f"{API}{path}"
    if team:
        sep = "&" if "?" in path else "?"
        url += f"{sep}teamId={team}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read() or b"{}")
            return resp.status, payload
    except urllib.error.HTTPError as exc:
        raw = exc.read() or b"{}"
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw.decode(errors="replace")[:300]}
        return exc.code, payload


def load_env(path: pathlib.Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True, help="Vercel access token")
    ap.add_argument("--project", required=True, help="Vercel project id (prj_...)")
    ap.add_argument("--team", default="", help="Vercel team id (team_...; optional)")
    ap.add_argument("--dry-run", action="store_true", help="list what would sync")
    args = ap.parse_args()

    env = load_env(pathlib.Path(__file__).resolve().parents[1] / ".env")
    wanted = {k: v for k, v in env.items() if k.startswith(INCLUDE_PREFIXES)}
    if not wanted:
        print("ERROR: no matching vars found in .env")
        return 2

    if args.dry_run:
        print("DRY-RUN: would sync these keys to production:")
        for k in sorted(wanted):
            print(f"  {k}")
        return 0

    # 1) existing env vars on the project (production target)
    status, payload = _request(
        args.token,
        "GET",
        f"/v10/projects/{args.project}/env?target=production&decrypt=false",
        team=args.team,
    )
    if status != 200:
        print(f"ERROR: list env failed HTTP {status}: {json.dumps(payload)[:300]}")
        return 1
    existing = {
        item["key"]: item["id"]
        for item in payload.get("envs", [])
        if "production" in (item.get("target") or [])
    }
    print(f"existing production env vars on project: {len(existing)}")

    # 2) delete stale vars that exist on Vercel but not in local .env set
    for key, env_id in sorted(existing.items()):
        if key not in wanted:
            status, payload = _request(
                args.token,
                "DELETE",
                f"/v10/projects/{args.project}/env/{env_id}",
                team=args.team,
            )
            if status in (200, 204):
                print(f"  deleted stale {key}")
            else:
                print(f"  WARN delete {key} HTTP {status}: {json.dumps(payload)[:200]}")

    # 3) upsert wanted vars (create if missing, else update in place)
    for key in sorted(wanted):
        if key in existing:
            status, payload = _request(
                args.token,
                "PATCH",
                f"/v10/projects/{args.project}/env/{existing[key]}",
                {"key": key, "value": env[key], "type": "plain", "target": ["production"]},
                team=args.team,
            )
        else:
            status, payload = _request(
                args.token,
                "POST",
                f"/v10/projects/{args.project}/env",
                {"key": key, "value": env[key], "type": "plain", "target": ["production"]},
                team=args.team,
            )
        ok = status in (200, 201)
        print(f"  {'OK ' if ok else 'FAIL'} {key} (HTTP {status})")
        if not ok:
            print(f"       {json.dumps(payload)[:250]}")

    print("sync complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
