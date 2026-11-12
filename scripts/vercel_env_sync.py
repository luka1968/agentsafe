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
import time

import requests

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
    "SMTP_",      # Report delivery SMTP configuration
    "NOTIFY_FROM",# Email sender address for report notifications
)


def _request(
    token: str, method: str, path: str, body: dict | None = None, team: str = ""
) -> tuple[int, dict]:
    url = f"{API}{path}"
    if team:
        sep = "&" if "?" in path else "?"
        url += f"{sep}teamId={team}"
    headers = {"Authorization": f"Bearer {token}"}
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            resp = requests.request(
                method,
                url,
                json=body,
                headers=headers,
                timeout=(15, 45),
            )
            if resp.status_code in (200, 201, 204):
                try:
                    return resp.status_code, resp.json()
                except ValueError:
                    return resp.status_code, {}
            try:
                return resp.status_code, resp.json()
            except ValueError:
                return resp.status_code, {"raw": resp.text[:300]}
        except requests.RequestException as exc:  # TLS reset / timeout: retry
            last_err = exc
            time.sleep(1.5 * (attempt + 1))
    return 0, {"error": f"request failed after retries: {last_err}"}


def load_env(path: pathlib.Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        # strip wrapping quotes so values land on Vercel without literal " chars
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        env[key.strip()] = value
    return env


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True, help="Vercel access token")
    ap.add_argument("--project", required=True, help="Vercel project id (prj_...)")
    ap.add_argument("--team", default="", help="Vercel team id (team_...; optional)")
    ap.add_argument("--dry-run", action="store_true", help="list what would sync")
    ap.add_argument(
        "--prune",
        action="store_true",
        help="DELETE project env vars that are NOT in the local .env set "
        "(default: leave unknown vars untouched)",
    )
    args = ap.parse_args()

    env = load_env(pathlib.Path(__file__).resolve().parents[1] / ".env")
    wanted = {k: v for k, v in env.items() if k.startswith(INCLUDE_PREFIXES)}
    if not wanted:
        print("ERROR: no matching vars found in .env")
        return 2

    # existing env vars on the project (production target)
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

    to_create = sorted(k for k in wanted if k not in existing)
    to_update = sorted(k for k in wanted if k in existing)
    stale = sorted(k for k in existing if k not in wanted)

    print(f"\nPLAN (local .env -> Vercel production):")
    print(f"  create {len(to_create)}: {to_create}")
    print(f"  update {len(to_update)}: {to_update}")
    print(f"  keep-untouched {len(stale)}" + (f" (would DELETE with --prune): {stale}" if stale else ""))

    if args.dry_run:
        print("\nDRY-RUN: no changes made.")
        return 0

    # 2) optional prune: delete vars present on Vercel but not in .env
    if args.prune:
        for key in stale:
            status, payload = _request(
                args.token,
                "DELETE",
                f"/v10/projects/{args.project}/env/{existing[key]}",
                team=args.team,
            )
            if status in (200, 204):
                print(f"  deleted stale {key}")
            else:
                print(f"  WARN delete {key} HTTP {status}: {json.dumps(payload)[:200]}")
    else:
        print(f"\n(--prune not set: leaving {len(stale)} unknown vars untouched)")

    # 3) upsert wanted vars (create if missing, else update in place)
    for key in to_create + to_update:
        if key in existing:
            status, payload = _request(
                args.token,
                "PATCH",
                f"/v10/projects/{args.project}/env/{existing[key]}",
                {"key": key, "value": env[key], "type": "plain", "target": ["production"]},
                team=args.team,
            )
            # Vercel refuses to change a Sensitive (secret) var to plain.
            # Recreate as plain: delete + create (the user asked for plain so
            # values stay viewable in the dashboard).
            if status == 400 and "type" in json.dumps(payload).lower():
                del_status, del_payload = _request(
                    args.token,
                    "DELETE",
                    f"/v10/projects/{args.project}/env/{existing[key]}",
                    team=args.team,
                )
                if del_status in (200, 204):
                    status, payload = _request(
                        args.token,
                        "POST",
                        f"/v10/projects/{args.project}/env",
                        {"key": key, "value": env[key], "type": "plain", "target": ["production"]},
                        team=args.team,
                    )
                    print(f"  recreated-as-plain {key} (HTTP {status})")
                else:
                    print(f"  WARN delete-for-recreate {key} HTTP {del_status}")
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
