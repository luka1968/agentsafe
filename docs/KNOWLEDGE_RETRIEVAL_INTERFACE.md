# Knowledge Retrieval Interface (stable) — for the next audit-engine phase

This document is the stable contract for how specialist agents retrieve security
knowledge. It is the entry point the next AgentSafe audit-engine upgrade can
adopt **without replacing the knowledge base**. Everything below is implemented
and verified in this repository (live Neon KB + JSONL fallback); nothing is
aspirational and no metric is synthesized.

- Entry point: `agentsafe.knowledge.interface.retrieve(kb, KnowledgeRequest) -> KnowledgeResponse`
- Schema: `agentsafe.knowledge.interface.describe()` (machine-readable)
- Version: `agentsafe.knowledge.interface.INTERFACE_VERSION`

---

## 1. Request (structured context)

```python
from agentsafe.knowledge.interface import KnowledgeRequest

KnowledgeRequest(
    query="stale Chainlink price used for liquidation",  # primary probe text
    agent="oracle",                 # agent identity -> resolves a retrieval profile
    category="oracle",              # vulnerability category hint
    profile=None,                   # optional explicit profile (overrides agent)
    depth=3,                        # requested retrieval depth (hard-capped at MAX_SEARCH_LIMIT=10)
    intent="discovery",             # "discovery" | "validation"
    solc="0.8",                     # solidity version requirement (soft match)
    code="(, int p, , uint updatedAt, ) = feed.latestRoundData(); use(p);",  # function/code context
    functions=["liquidate", "getPrice"],
    state_vars=["lastPrice", "collateral"],
    external_interactions=["feed.latestRoundData"],
    context=None,                   # or a ContractContext from intel/contract.py
    kb_groups=None, categories=None, tags=None, sources=None,  # optional hard filters
    include_counterexamples=True,
    min_relevance=0.0,              # optional: drop weak candidates
)
```

`to_context()` merges an explicit `ContractContext` with the structured fields
(functions / state vars / external interactions / solc / category) without
mutating the caller's context, so callers can pass either a full contract
context or just a few fields.

## 2. Response (normalized, honest)

`KnowledgeResponse.records[]` — each record view:

| field | meaning |
|---|---|
| `id`, `external_record_id` | stable identifiers |
| `title`, `category`, `subcategory`, `severity` | classification |
| `validation_status` (`verification_status`), `quality_status`, `claim` | validation + data-quality status |
| `source` | `{name, url, external_record_id}` — provenance preserved |
| `technical_explanation` | `root_cause` (or `mechanism`) |
| `exploit_pattern` | `{preconditions, attack_entry, attack_scenario, impact}` |
| `code` | `{vulnerable, corrected}` |
| `counterexample` | `{why_safe, fp_patterns, evidence_required, known_limitations, ...}` when the record is a false-positive reference |
| `retrieval` | `{why, signals, vector_rank, lexical_rank, matched_legs, context_signals, ...}` — the *reason* it matched |

`KnowledgeResponse.counterexamples[]` — the same view for false-positive records
(kb_group E/F) retrieved for the request's signals.
`KnowledgeResponse.validated()` — records carrying independent validation
(`curated` / `reproduced`), for the validation use case.

`KnowledgeResponse.metadata` — `mode` (`hybrid|lexical`), `degraded`,
`vector_used`, `lexical_used`, `degradation_reason`, `intent`, `agent`,
`profile`, `depth`, `solc`, `context_present`, `filters`, `record_count`,
`counterexample_count`, `validated_count`, `retrieved_at`,
`supporting_evidence: true`, and a `note`. When retrieval is degraded the note
is prefixed `DEGRADED RETRIEVAL (...) - results may be incomplete.`.

## 3. Intents

- `intent="discovery"` — find relevant mechanisms; ranked retrieval + context
  matching; returns matching records and counterexamples.
- `intent="validation"` — corroborate or refute a specific claim; uses the
  `validation` focus and a larger counterexample set, and exposes
  `response.validated()`.
- Counterexamples are **supporting evidence, never a verdict** (see §5).

## 4. Usage

```python
from agentsafe.knowledge import get_knowledge_store
from agentsafe.knowledge.interface import KnowledgeRequest, retrieve
from agentsafe.intel.render import render_kb_snippets
from agentsafe.knowledge.falsepositives import render_counterexamples

store = get_knowledge_store(settings)          # Neon hybrid, or JSONL fallback
resp = retrieve(store, KnowledgeRequest(
    agent="oracle", category="oracle",
    query="stale price for liquidation",
    code=open("Vault.sol").read(),
    solc="0.8", depth=3, intent="discovery"))

prompt_kb = render_kb_snippets(resp.records)                    # untrusted KB context
prompt_fp = render_counterexamples(resp.counterexamples, [])    # FP checklist
```

## 5. Safety / reliability semantics (Phase 9)

- **Never presents partial retrieval as full success.** `search()` reports a
  per-call status: `mode`, `degraded`, `vector_used`, `lexical_used`, `reason`,
  `empty`/`returned`. The interface surfaces this in `metadata` (`degraded`,
  `degradation_reason`). A configured embedder that contributes nothing marks
  `degraded=True`.
- **Connection failures** are retried (`_connect`, 3× backoff); `search` wraps
  each leg so a leg failure degrades to the other leg instead of raising.
- **Embedding failures** are caught at the leg (`retrieval_vector_fallback`) and
  in imports (vectors stored `NULL`); nothing is faked.
- **Query timeouts**: retrieval connections set `statement_timeout` from
  `KB_STATEMENT_TIMEOUT_MS` (default 15 s); migrations/imports are exempt.
- **Missing vectors**: `knowledge.integrity.backfill_missing_embeddings`.
- **Dedup / provenance**: `content_hash UNIQUE` + `(source_id,
  external_record_id) UNIQUE` + `ON CONFLICT DO NOTHING`; imports never
  overwrite existing records.
- **No destructive migration**: the one latent vector-dim change backs the old
  vectors up losslessly (`knowledge_embeddings_backup_dim`) and refuses to drop
  if the backup is incomplete.

## 6. Verified data flow (current callers)

- `scripts/run_audit.py` → `kb_store_factory=lambda: get_knowledge_store(settings)`
  → `agents/scheduler.py` attaches `kb` to `AnalysisMaterial`.
- `agents/base.py` — specialists call `retrieve_for_agents` (context-aware
  discovery) and `retrieve_counterexamples` (Phase 6).
- `orchestrator.py` — corroborates each finding via `kb.search(..., profile="validation")`.

The interface in §1 is the superset those callers already exercise; adopting it
requires no KB change.

## 7. Verification

- Tests: `tests/test_kb_interface.py` (incl. a data-flow lock), `tests/test_kb_safety.py`,
  `tests/test_kb_falsepositives.py`, `tests/test_kb_context.py`,
  `tests/test_kb_rerank.py`, `tests/test_kb_integrity.py`,
  `tests/test_benchmark_retrieval.py`.
- Retrieval benchmark: `benchmarks/kb_retrieval_bench.py` →
  `benchmarks/results/kb_retrieval_bench.json` (14 classes, K=5):

| mode | P@5 | R@5 | MRR | irrelevant rate |
|---|---|---|---|---|
| vector-only | 0.683 | 0.212 | 0.958 | 0.317 |
| lexical-only | 0.667 | 0.134 | 0.701 | 0.333 |
| **hybrid** | **0.767** | **0.219** | 0.958 | **0.233** |

Counterexample retrieval rate 1.0 (EVM-rollback + send/call cases); source
references preserved 1.0; vector-leg-empty rate 0.0. Recall is **curated-anchored**
(no exhaustive labeled corpus exists); absolute recall and a true
embedding-failure rate cannot yet be measured reliably and are stated as such.

## 8. Defects fixed in this workstream (Stage 4)

1. Production worker never received `NEON_DATABASE_URL` / `NVIDIA_API_KEY` →
   silently ran the 14-record JSONL KB lexical-only. Fixed in both workflows +
   compose; degradation now logged.
2. `normalize_record` discarded adapter provenance (`contest`/`issue_id`) on the
   double-normalization path → restored + backfilled (841 records).
3. Bulk records carried no root cause / attack scenario / preconditions → LLM
   enrichment (root cause 99.2%, preconditions 99.5%).
4. Stale/missing embeddings after enrichment → backup + stale-only re-embed.
5. Latent destructive vector-dim migration → mandatory lossless backup or abort.
6. Silent partial retrieval → per-call degraded status surfaced through the
   interface.
