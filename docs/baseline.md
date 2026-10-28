# AgentSafe Capability Baseline (pre-upgrade)

Measured on 2026-10-27 against live audits of `0x00000022dA000002656c64D9eA6011ea952D008A`
(FraxProxy: TransparentUpgradeableProxy, 13 files, verified source v0.8.23).
All numbers below come from real `report.json` artifacts, not marketing claims.

## Current detection capabilities

- Static tools: Slither 0.10.4, Aderyn 0.6.8, Mythril 0.24.3, Heimdall 0.9.2
  (4/4 executed on the FraxProxy target; 0 static findings — the code is a thin
  OZ proxy wrapper).
- LLM agents: access_control, fund_flow, business_logic (post-dedup) plus a
  deterministic validation stage (Section 3 rules).
- Best run after reasoning-content + token-budget fixes
  (task `S9X8KXWYAj1uShyztEjY8e-o`): 5 findings, 16 LLM calls,
  0 failed calls, 2 findings on the core `src/FraxProxy.sol`,
  `failed_calls: 0`, single limitation (business_logic truncation at 30k chars —
  since raised to 45k in commit 56131dc).

## Known false positives (user-scored report, 3/10)

Same run family (task `H_nauXcuIjSXyrL7RfuFeVkT`, 6 findings, all OZ-standard
library noise):

1. "Immutable admin prevents admin change" — misreads OZ transparent-proxy
   design (admin is intentionally the ProxyAdmin instance).
2. "No access control on upgradeToAndCall" — ignores the `msg.sender ==
   _proxyAdmin()` check in `_fallback()` (governance advice, not a bug).
3. "Unprotected changeAdmin / upgradeBeaconToAndCall / upgradeToAndCall" (x3)
   — internal-only functions reported as externally reachable. Duplicated the
   same theme 3–4 times.
4. "_implementation() allows upgrades" — evidence is a `view` function; the
   claim contradicts the evidence.

Root causes identified: single-agent coverage (only access_control completed),
no notion of internal-vs-external reachability, no dedup-by-mechanism, no
library-file downranking, and reasoning models returning empty `content`
(long-prompt thinking exhausted the 3000-token output budget — fixed by
`LLM_MAX_OUTPUT_TOKENS=8000` + `reasoning_content` fallback, commits
e25a64d/62757ba/df8c9a9).

## Known missed vulnerabilities

Not established systematically (no benchmark run yet). Observed coverage gaps:
business_logic agent truncated (`exceeded 30000 chars`) in run S9X8 before the
45k raise; fund_flow/business_logic ran only after the token fix. Cross-function
and multi-step exploit-path analysis does not exist yet — agents see file
chunks, not call graphs.

## Analyzer failures observed

- `xin` provider: HTTP 401 (dead key) — router skips it.
- `xin2` provider: 429 rate-limited from GitHub Actions egress IPs.
- `harbor` (deepseek-v4-flash:free): reasoning model; without the
  8000-token budget it burned all tokens on thinking and returned empty
  content (`SchemaValidationError: empty_response`).
- Mythril/Heimdall often report `exit_code: null` in tool_executions (container
  timeout semantics) — findings still absent; treated as executed.

## Execution cost and duration (measured)

- Full audit wall clock: ~1069–1550s (18–26 min) for the 13-file proxy.
- LLM usage (best run): 16 calls, 88,017 prompt tokens, 79,906 completion
  tokens, harbor free-tier model → $0 marginal LLM cost.
- Static stage: mythril ~307s is the dominant fixed cost.

## Interfaces that must remain compatible

- MCP tools: `audit_contract`, `check_audit_status`, report REST
  (`/api/audit/{task_id}/report{,.json,.pdf}`) — unchanged.
- GitHub Actions worker (docker-audit.yml dispatch contract), report artifact
  zip `report.json`, task store schema — unchanged.
- x402 payment verification, access tokens, pricing — unchanged.
- `Finding` schema, `LLMFindingsPayload` wire format, severity rubric,
  validation rules (Section 3), 435-test suite must stay green.

## Upgrade targets (this version)

1. Contract Intelligence Layer (`src/agentsafe/intel/`): deterministic static
   extraction (functions, modifiers, state vars, read/write sets, call graph,
   transfers, arithmetic, proxy patterns) from verified source, plus slither
   JSON enrichment when available. Never invents missing bodies; tracks
   unresolved externals explicitly.
2. Security Knowledge Base (`src/agentsafe/knowledge/`): small, high-quality,
   versioned, provenance-carrying JSONL dataset of public vulnerability
   mechanisms + lexical retrieval, injected as untrusted context so agents must
   argue whether the mechanism applies.
3. Agent prompt integration: intel brief + KB snippets per focus area,
   injection-contained, budget-fitted.

## Post-upgrade results (this build)

Implemented and tested; all 468 tests green (435 pre-upgrade + 33 new).

**Contract Intelligence Layer** — `src/agentsafe/intel/`:
- Deterministic extractor (no slither Python dependency — the worker runs
  slither as a CLI): contracts/interfaces/libraries, inheritance bases,
  state vars, events, modifiers; per-function visibility/mutability/returns/
  modifiers; per-body read/write sets (by state-var symbol), internal call
  edges, external `target.member()` calls, ether/delegatecall sites, token
  calls, arithmetic op sets, `unchecked` count, guards, emitted events;
  ERC-1967/transparent-proxy/upgrade hints; privileged + initializer function
  lists. Never invents bodies (interfaces yield zero functions); interface-
  typed state vars (`token.transfer`) are flagged as unresolved externals.
- Call graph helpers: `callers_of`, `writers_of`/`readers_of` (state-dependency
  map), `external_entry_points`. Stable 1-indexed line numbers; comment
  stripping preserves lines.
- `enrich_from_slither_json()` merges Slither detector JSON when available;
  unparsable JSON degrades to a warning, never a crash.
- Focus-aware renderer (`render_intel_brief`) caps at 2400 chars and always
  surfaces unresolved externals + extraction warnings (honesty guarantee).

**Security Knowledge Base** — `src/agentsafe/knowledge/`:
- `dataset/v1.jsonl`: 14 high-quality, versioned records written in own words
  from public sources (rekt.news postmortems, SWC registry, OZ docs), each
  carrying source, URL, license, protocol_type, category, mechanism, root
  cause, preconditions, exploit sequence, impact, remediation, keywords.
  Categories: reentrancy (incl. read-only), access-control, initialization,
  proxy/storage-collision, unhandled-return, oracle+flash-loan, governance
  flash-loan, approval race, rounding/ERC4626 first-depositor, fee-on-transfer
  accounting, donation/first-depositor, bridge signature, proxy upgrade
  front-run.
- Loader is fail-fast: missing provenance or non-list keywords raise; missing
  file → empty KB (graceful).
- Lexical retrieval (TF-IDF-style scoring, stopword/len filters) + focus-
  category rerank (1.6× boost). Local in-memory index — no paid vector DB,
  no fine-tune.
- Rendered snippets are hard-capped (1600 chars), wrapped in UNTRUSTED KB
  CONTEXT markers, and each forces the applicability question: the agent must
  explain whether the mechanism applies, citing code evidence, or discard it.
  Retrieved content is never executed and can never override the system
  prompt (it sits after the system prompt, inside the user turn).

**Integration** (`orchestrator.py`, `agents/base.py`):
- Orchestrator builds intel from `bundle.files` (path→content) and loads the
  default KB once; failures become limitations, never audit failures.
- `AnalysisMaterial` gains `intel` + `kb`; agents render a per-focus intel
  brief once per call and per-chunk KB snippets. Pseudo-source audits skip
  intel (honest degradation).
- The 468-test suite covers the extractor, slither enrichment, renderer
  budgets/markers, KB loader validation, retrieval ordering/rerank, and the
  wire-through (test_orchestrator exercises a real SourceBundle path).

Not done (explicitly out of scope for this version): fine-tuning; paid vector
DB; semantic embeddings service; benchmark-verified parity claims with
AgentLISA (no private KB access; no benchmark evidence). These remain future
targets and are not claimed.
