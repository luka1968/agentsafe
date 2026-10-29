# Stage 10 — Benchmarking & Regression Evaluation

This document is the honest accounting of what AgentSafe's Stage-10
evaluation measures, on which data, with which model configurations, and —
critically — what it does **not** claim. All metrics below come from **actual
execution** in this repository; none are synthesized. No claim is made that
AgentSafe matches or surpasses AgentLISA without a fair, reproducible
comparison on the same held-out set.

---

## 1. Dataset verification (live, not assumed)

Every candidate was probed against its live source (`scripts/probe_datasets.py`,
`scripts/probe_github.py`) on 2026-08. Verdicts:

| Dataset | Location (verified) | License | Format / size | Usable? |
|---|---|---|---|---|
| **SPECA** | HF `NyxFoundation/vulnerability-reports`, config `default`, split `train` | MIT | 4,470 rows; fields `id/source_platform/contest/issue_id/severity/title/description/source_url/domain/scraped_at` | ✅ imported → Neon KB (`speca-code4rena`, 267 records) |
| **LISABench** | GitHub `agentlisa/bench` (default branch `main`) | MIT | 10,187 JSON records; fields `Title/Content/Impact/Source/Code`; `Code` = real per-contest source files | ✅ detection vulnerable set |
| **SCAR** | GitHub `scarai-xyz/scar-retrieval` | Apache-2.0 | pipeline code + corpus loader only; dataset requires Solodit API access | ⚠️ not directly usable without Solodit key |
| **C4Audit** | GitHub `lucianasi/C4Audit` | **no license** | 44 KB + `reports_code4rena.txt` | ❌ no license → not used |
| **GitmateAI** | HF `GitmateAI/solidity_vulnerability_audit_dataset` | Apache-2.0 | `instruction/input/output` teaching samples (small synthetic contracts) | ⚠️ validation auxiliary only (teaching-quality) |
| **known-safe** | OpenZeppelin `openzeppelin-contracts` tag `v5.0.0` | MIT | `ERC20.sol` reference implementation | ✅ reference-safe (NOT formally verified) |

**Verification evidence** committed at `benchmarks/data/provenance.json`
(subset ids, fetch times, URLs, licenses, sha256 of reference contracts).

**Anti-leakage notes.**
- Retrieval pool = code4rena-only SPECA. Queries are SPECA records sampled
  held-out by seed; LISABench (sherlock/codehawks) records are **not** used as
  queries because they have no ground-truth counterpart in a code4rena-only KB
  — using them would make recall meaningless.
- Detection vulnerable set = LISABench source files; known-safe = OpenZeppelin.
  The probe detection layer (contract-intel graph) is a **different mechanism**
  than the keyword-anchored ground-truth extractor, so there is no
  protocol-level leakage between the two.

---

## 2. Four separated evaluations

Run harness: `benchmarks/eval_suite.py` (writes JSON under
`benchmarks/results/`). All numbers below are from actual runs.

### 2.1 Retrieval (RAG quality) — `--mode retrieval --rag on`
Pool: live Neon KB (SPECA, 2048-d NVIDIA embeddings, no HNSW). Protocol =
`benchmarks/retrieval_bench.py` self-retrieval: query = record's discriminative
title; ground truth = its id; seed-held-out sampling. Model:
`nvidia/nemotron-3.5-embed-1b` (query input_type, truncate END).

Result (n=12, seed=42):

| leg | R@1 | R@3 | R@5 | MRR |
|---|---|---|---|---|
| vector | 0.667 | 0.667 | 0.750 | 0.706 |
| lexical (ts_rank, not BM25) | 0.583 | 0.583 | 0.583 | 0.593 |
| RRF-fused | 0.500 | 0.667 | 0.833 | 0.640 |

### 2.2 Vulnerability detection — `--mode detection`
Vulnerable = LISABench source bundles; known-safe = OpenZeppelin ERC20.
Pipeline = full orchestrator with **deterministic probe LLM** (see §5) → the
numbers measure AgentSafe's **static intelligence layer** (forge/solc compile +
contract-intel graph + validation funnel), *not* a frontier model.

Result (n=6, seed=42, RAG off): macro P=0.556, R=0.625, F1=0.588; per-category
TP/FP/FN; severity exact-match 0.0 (probe conservatively labels low); tool
execution success 0.25 (forge 6/6; slither/aderyn/mythril/heimdall not
installed). Full per-sample table in the artifact. Known finding: the intel
probe layer over-flags any contract with arithmetic + external calls, so
low-GT samples incur FP — an honest static-layer ceiling, not the full system.

### 2.3 Validation accuracy — `--mode validation`
Deterministic labeled set (`validation_bench.py`), locked by
`tests/test_stage10_bench.py`: accuracy 1.0, false-positive rate 0.0,
regression guards pass (CEI-compliant reentrancy never confirmed; theoretical
overflow never confirmed even with a detector flag).

### 2.4 End-to-end audit performance — `--mode e2e`
Full pipeline per contract (RAG off): mean 1.08 s/contract (n=2, probe LLM,
no paid calls → cost USD 0.0), 10/10 stages complete, validation success 1.0.
RAG-on runtime not reported here: live Neon round-trips dominated local
latency and timed out; RAG-on *deployment* latency must be measured in the
hosted environment, not this sandbox (see §5).

### 2.5 RAG on vs off (honest scoping)
Retrieval metrics (§2.1) are the RAG-on signal. In **probe** mode the detection
and e2e legs are identical RAG on/off because the
intel layer does not consume KB context. A meaningful RAG on/off ablation of
*end-to-end detection* requires **live LLM mode** (`--llm live`), which makes
real provider calls per specialist with KB-augmented prompts. We do not claim a
live-model RAG delta; running `--llm live` consumes paid provider tokens and is
out of scope for the deterministic benchmark, but the harness supports it.

---

## 3. Model & configuration record

- Retrieval embedder: `nvidia/nemotron-3.5-embed-1b`, 2048-d, query input_type,
  `truncate="END"`. Config via env (`NVIDIA_API_KEY`, `NVIDIA_EMBED_MODEL`,
  `NVIDIA_BASE_URL`, `EMBED_DIM`). Not fake vectors — all vectors are live API
  outputs, previously imported into Neon.
- Detection/e2e probe LLM: deterministic `IntelProbeAgent` (contract-intel
  graph → candidate findings) + zero-finding `ProbeRouter` for the 7 routed
  specialists. No provider call, no token cost. This isolates the static layer;
  `--llm live` swaps in the configured provider (paid).
- Tools: forge 1.8.3 present; slither/aderyn/mythril/heimdall absent → their
  execution is recorded as `executed=False` (honest tool accounting).
- Seeds: retrieval 42, detection 42, e2e 42. All subsets cached under
  `benchmarks/data/` with provenance.

## 4. Reproduce

    # WSL (offline legs)
    .venv-test/bin/python benchmarks/eval_suite.py --mode detection --rag off --n-detection 6 --seed 42
    .venv-test/bin/python benchmarks/eval_suite.py --mode validation
    .venv-test/bin/python benchmarks/eval_suite.py --mode e2e --rag off --n-e2e 2 --seed 42

    # Windows (live Neon + NVIDIA for the vector retrieval leg)
    .venv/Scripts/python.exe benchmarks/eval_suite.py --mode retrieval --rag on --n-retrieval 12 --seed 42

## 5. Limitations (deliberate, not hidden)

1. Detection metrics reflect the **static intel layer only** in probe mode. A
   live-model run is required to report system-level detection P/R/F1; we
   explicitly do not claim such numbers here.
2. Severity exact-match is 0.0 because the probe conservatively labels `low`.
   This is a probe artifact, not a claim about severity calibration.
3. RAG-on end-to-end latency was not measured (Neon round-trips timed out in
   this sandbox). RAG-on latency must be evaluated in the hosted deployment.
4. Lexical retrieval uses PostgreSQL `ts_rank`, which is **not** BM25; no BM25
   claim is made.
5. `known-safe` = widely-audited reference implementations, **not** formally
   verified; they are labeled reference-safe only.
6. No comparison against AgentLISA is made anywhere in this document because no
   fair, reproducible cross-run on the same held-out set has been executed.
