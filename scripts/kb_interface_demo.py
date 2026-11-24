#!/usr/bin/env python
"""Phase 7 — verify the specialist retrieval interface with REAL requests.

Issues structured discovery and validation requests against the configured KB
(Neon hybrid when NEON_DATABASE_URL + embedder are set, else the JSONL fallback)
and prints the normalized response + retrieval metadata. Read-only.

    python scripts/kb_interface_demo.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
ROOT = Path(__file__).resolve().parents[1]


def _load_env() -> dict:
    env = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _store():
    dsn = os.environ.get("NEON_DATABASE_URL", "").strip()
    if not dsn:
        from agentsafe.knowledge.kb import KnowledgeBase
        return KnowledgeBase.load_default(), "jsonl"
    from agentsafe.knowledge.db import NeonKnowledgeStore
    try:
        from agentsafe.knowledge.embeddings import get_embedder
        emb = get_embedder()
    except Exception:
        emb = None
    return NeonKnowledgeStore(dsn=dsn, vector_dim=2048, embedding_model=emb), \
        ("hybrid" if emb else "lexical")


def main() -> int:
    for k, v in _load_env().items():
        os.environ.setdefault(k, v)
    from agentsafe.knowledge.interface import KnowledgeRequest, describe, retrieve

    store, mode = _store()
    print(f"store mode: {mode}")
    print("interface:", json.dumps(describe(), indent=1)[:600], "\n")

    requests = [
        KnowledgeRequest(
            agent="oracle", category="oracle",
            query="stale Chainlink price used for liquidation",
            code="(, int p, , uint updatedAt, ) = feed.latestRoundData(); use(p);",
            functions=["liquidate", "getPrice"],
            state_vars=["lastPrice", "collateral"],
            external_interactions=["feed.latestRoundData"],
            solc="0.8", depth=3, intent="discovery"),
        KnowledgeRequest(
            agent="cross_function", category="reentrancy",
            query="external call before state update reentrancy",
            code="(bool ok,) = msg.sender.call{value: amt}(\"\"); b[msg.sender]-=amt;",
            functions=["withdraw"], state_vars=["balances"], depth=3,
            intent="discovery"),
        KnowledgeRequest(
            agent="validation", category="token-transfer",
            query="send() failure not detected loses funds",
            code="payable(to).send(amt); balances[msg.sender] -= amt;",
            depth=3, intent="validation"),
    ]

    for i, req in enumerate(requests, 1):
        resp = retrieve(store, req)
        print("=" * 80)
        print(f"REQUEST {i}: agent={req.agent} intent={req.intent} "
              f"cat={req.category} depth={req.depth}")
        print("metadata:", json.dumps(resp.metadata))
        for r in resp.records:
            print(f"  REC [{r['id']}] {r['category']} val={r['validation_status']}"
                  f" :: {str(r['title'])[:64]}")
        for c in resp.counterexamples:
            print(f"  FP  [{c['id']}] :: {str(c['title'])[:64]}")
        if req.intent == "validation":
            print("  independently-validated records:",
                  [v["id"] for v in resp.validated()])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
