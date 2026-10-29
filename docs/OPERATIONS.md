# Stage 11 — Production Readiness & Operational Controls

Scope of this stage: **security and operational hardening only**. No pricing,
payment, x402, USDC-decimal, access-token, MCP, or GitHub Actions behavior was
changed. Every existing test for those surfaces still passes unchanged
(606 passed + 5 skipped).

---

## 1. Security posture (Stage 11 controls)

| Control | Status | Where |
|---|---|---|
| Credentials server-side only | ✅ pre-existing + audited | `config.py` reads env; `mask_secret` on cloud echo; `api/index.py` never emits keys |
| Import/admin endpoints protected | ✅ no admin HTTP surface exists (imports are CLI/scripts); all REST endpoints gated (x402 or bearer task-id) | `server.py` |
| Input validation | ✅ address normalization, source-size cap (5,000 lines), task-id length cap, JSON-object body check | `server.py` |
| Rate limits (HTTP) | ✅ new: per-client-IP sliding window on `POST /api/audit` + report GETs (`HTTP_RATE_LIMIT_PER_MINUTE`, default 20/min), 429 response | `server.py` `_SlidingWindowLimiter` |
| Bounded body size | ✅ new: `HTTP_MAX_BODY_BYTES` (default 256 KiB) checked pre-read (Content-Length) and post-read (chunked); 413 response | `server.py` |
| Bounded batch sizes | ✅ pre-existing: embedding batch 20; REST audit cap 500 lines; scheduler bounded concurrency | `importers.py`, `server.py`, `scheduler.py` |
| Safe transactions + parameterized SQL | ✅ pre-existing (audited): all queries parameterized; f-string only for internal schema constants | `knowledge/db.py` |
| No secret/source logging | ✅ pre-existing (audited): logger never emits keys/tokens; `mask_error_details=True` | `server.py`, `router.py` |
| Embedding reuse for unchanged content | ✅ new: `_plan_embeddings` — content_hash already stored with vector → never re-embedded; re-running an import makes zero embedder calls for unchanged records | `knowledge/importers.py` |
| Operational metrics | ✅ new: counters + latency aggregates for imports, retrieval (incl. fallbacks), LLM usage, agent runs; optional JSONL sink; never payload content | `agentsafe/metrics.py` + hooks |
| Graceful retrieval degradation | ✅ pre-existing (now regression-locked): Neon outage → JSONL KB; embedder outage → lexical-only; empty result → `[]`, never fabricated | `knowledge/db.py`, tests |
| Deploy config preserved | ✅ unchanged (`vercel.json`, `Dockerfile*`, `docker-compose.yml`, workflows); only additive env vars | — |

## 2. New environment variables (all optional, with defaults)

```ini
HTTP_RATE_LIMIT_PER_MINUTE=20      # per-IP REST requests per minute (1..10000)
HTTP_MAX_BODY_BYTES=262144         # max audit body bytes (1024..10MB)
METRICS_JSONL_PATH=                # empty = disabled; else JSONL snapshot sink
```

## 3. Metrics surface (never payload content)

Keys are grouped counters and duration aggregates — no addresses, task ids,
source code, or secrets ever enter the metrics:

- `import_records`, `import_duplicates`, `import_failed`, `import_success`,
  `import_embedding_calls`, `import_*`
- `retrieval_calls`, `retrieval_latency_ms` (mean/max), `retrieval_vector_fallback`,
  `retrieval_neon_fallback`
- `llm_calls`, `llm_failed`, `llm_tokens_in`, `llm_tokens_out`
- `agent_runs`, `agent_failed`, `agent_duration_ms` (mean/max)
- `http_requests`, `http_rate_limited`, `http_body_rejected`, `http_bad_json`
- `audit_dispatched` (counted in orchestrator dispatch path)

Snapshot example:

```json
{"agent_runs": 4, "retrieval_calls": 12, "retrieval_latency_ms_mean": 18.4,
 "retrieval_latency_ms_max": 97.1, "http_rate_limited": 1, "ts": 1753920000.0}
```

## 4. Operational runbook

1. **Deploy** — unchanged: `vercel.json` / `Dockerfile.server` / workflows.
   Add the three new env vars if desired; otherwise defaults apply.
2. **Import a dataset** — CLI only (no HTTP import surface):
   `python -m agentsafe.knowledge.speca` (or the resumable importer). Re-runs
   are idempotent and now zero-cost for unchanged content (embedding reuse).
3. **Watch** — set `METRICS_JSONL_PATH` and tail the JSONL for
   `http_rate_limited` spikes (abuse), `retrieval_*_fallback` (embedder/Neon
   degradation), `llm_failed` (provider health), `agent_failed` (scheduler).
4. **Failure behavior** — retrieval degrades gracefully (Neon→JSONL,
   vector→lexical) and the audit pipeline never fabricates KB results;
   per-stage failures are isolated and surfaced in the report's limitations.
5. **Incident guidance** — raise/lower `HTTP_RATE_LIMIT_PER_MINUTE` without
   redeploy; 429/413 responses are structured JSON with `error_code`.

## 5. Remaining risks / limitations

1. Rate limiter is **in-memory per process** — multiple serverless instances
   have independent buckets. For strict global limits, front with a CDN/WAF
   rate rule; the limiter here is defense-in-depth per instance.
2. Metrics are aggregate in-memory + optional file sink; a hosted metrics
   pipeline (e.g. Prometheus) is out of scope but the snapshot dict is
   serializable.
3. Embedding-reuse lookup adds one indexed query per import run (negligible).
4. `known-safe` reference contracts are widely-audited but not formally
   verified (unchanged stance from Stage 10).
5. Live LLM RAG on/off ablation still requires `--llm live` (paid) — the
   deterministic probe numbers are the intel-layer ceiling, not the full
   system (unchanged from Stage 10).

## 6. Production readiness: **PASS** (Stage 11 scope)

- 606 tests pass (incl. 15 new Stage 11 control tests), 5 skipped (live-Neon
  / optional-dependency guards).
- No pricing/payment/x402/token/MCP/GH-Actions behavior modified; their
  existing tests all still pass unchanged.
- New controls are additive and opt-in via env defaults; existing deployment
  config untouched.
