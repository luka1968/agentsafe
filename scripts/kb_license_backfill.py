#!/usr/bin/env python
"""Backfill license_status / commercial_use for curated v1/v2 rows.

Requirement (Task 4/9): every record carries license + commercial-use status;
unknown rights are NEVER marked unrestricted. v1/v2 datasets store the license
under the `license` key (imported before the license_status column existed),
so their rows have NULL license_status in Neon.

NON-DESTRUCTIVE: fills NULL fields only; existing values are never overwritten.
commercial_use for v1/v2 is set to 'unspecified' (honest unknown marker), never
'unrestricted'. Idempotent: re-running changes nothing.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _load_env() -> dict:
    env = {}
    p = Path(__file__).resolve().parents[1] / ".env"
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def main() -> int:
    env = _load_env()
    for k, v in env.items():
        os.environ.setdefault(k, v)
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        print("NEON_DATABASE_URL not set", file=sys.stderr)
        return 2

    from agentsafe.knowledge.db import NeonKnowledgeStore

    store = NeonKnowledgeStore(dsn=dsn, vector_dim=2048)
    ds_dir = Path(__file__).resolve().parents[1] / "src" / "agentsafe" \
        / "knowledge" / "dataset"
    updated = 0
    for fname, src, default_cu in (
        ("v1.jsonl", "agentsafe-v1.jsonl",
         "proprietary (agentSAFE); per-record provenance"),
        ("v2.jsonl", "agentsafe-v2.jsonl", "unspecified"),
    ):
        rows = []
        for line in (ds_dir / fname).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("//"):
                rec = json.loads(line)
                rows.append((rec.get("id"), rec.get("license")
                             or "proprietary (agentSAFE); per-record provenance",
                             rec.get("commercial_use") or default_cu))
        with store._connect() as conn, conn.cursor() as cur:
            for eid, lic, cu in rows:
                if not eid:
                    continue
                cur.execute(
                    """
                    UPDATE vulnerability_knowledge
                    SET license_status = COALESCE(license_status, %s),
                        commercial_use = COALESCE(commercial_use, %s),
                        updated_at = now()
                    WHERE source_id = %s
                      AND (external_record_id = %s
                           OR external_record_id LIKE %s)
                      AND (license_status IS NULL OR commercial_use IS NULL)
                    """,
                    (lic, cu, src, eid, eid + "#chunk%"),
                )
                updated += cur.rowcount
    print("rows updated:", updated)
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute("""SELECT count(*) FILTER (WHERE license_status IS NULL) ls_null,
                              count(*) FILTER (WHERE commercial_use = 'unrestricted') unres,
                              count(*) total
                       FROM vulnerability_knowledge""")
        r = cur.fetchone()
        print(f"license NULL: {r['ls_null']}/{r['total']}; "
              f"marked unrestricted (must be 0): {r['unres']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
