# agentSAFE API Reference

**agentSAFE** is a commercial EVM smart-contract security auditor. It exposes two
interfaces over the same backend:

- **Model Context Protocol (MCP)** — tools for LLM agents (Claude, cursor, etc.)
- **REST** — curl / SDK consumers, x402-gated

Both are pay-per-call via [x402](https://x402scan.com) **USDC on Base**.
No API keys, no subscriptions — you pay only when the audit actually runs.

---

## 1. Base URL & Discovery

| Item      | Value                                            |
|-----------|--------------------------------------------------|
| Base URL  | `https://x402.workfern.com`                     |
| MCP       | `https://x402.workfern.com/mcp`                 |
| OpenAPI   | `https://x402.workfern.com/openapi.json`        |
| Refund    | `https://x402.workfern.com/refund`              |
| Network   | Ethereum Mainnet (audits only verified source)  |

All responses are JSON unless noted. Errors use the shape:

```json
{ "ok": false, "error_code": "snake_case", "error": "human-readable reason" }
```

---

## 2. MCP Tools

Connect any MCP client to `https://x402.workfern.com/mcp`. Five tools:

| Tool                | Paid | Description                                             |
|---------------------|------|---------------------------------------------------------|
| `health`            | free | Service status, pricing tiers, KB size, limits.        |
| `audit_contract`    | paid | Start a source audit for a verified Mainnet address.   |
| `check_audit_status`| free | Poll an audit; returns the report when complete.       |
| `get_contract_info` | free | On-chain snapshot (is contract, bytecode size, verified). |
| `get_source_code`   | paid | Standalone verified-source retrieval ($0.01 USDC).     |

### 2.1 `audit_contract(address)`

Starts an audit. **x402-gated**: an unpaid call returns the official `402`
payment-required challenge and never dispatches.

- **Response (paid accepted):** `{ "ok": true, "task_id": "...", ... }`
- **Response (payment required):** the standard x402 `402 PAYMENT-REQUIRED`
  body quoting the tier price; no audit is started.

### 2.2 `check_audit_status(task_id)`

Polls progress. Returns `{ "ok": true, "state": "...", "report": {...} }`
once the worker completes. `state` ∈ `queued | running | completed | failed`.

### 2.3 `health()`

```json
{
  "ok": true,
  "status": "ok",
  "pricing_tiers": [ {"up_to_lines": 100, "price": "$0.50"}, ... ],
  "knowledge_base_entries": 281
}
```

### 2.4 `get_contract_info(address)`

Free on-chain snapshot — no payment, no audit.

### 2.5 `get_source_code(address)`

Standalone verified-source retrieval at a flat **$0.01 USDC**. If the same
source was already fetched inside a paid audit, no additional charge applies
(the audit tier already covers it).

---

## 3. REST Endpoints

### 3.1 `POST /api/audit`

x402-gated audit dispatch. Body: `{ "address": "0x..." }`.

**Source-size guard runs before settlement** — a paid request that cannot be
served at the advertised tier never moves funds.

**Success (202):**

```json
{
  "ok": true,
  "task_id": "ba7f0c9d...",
  "state": "queued"
}
```

**x402 payment-required (402):** standard challenge with `PAYMENT-REQUIRED`
header and quoted tier price. No audit is started until payment.

### 3.2 Report retrieval (task-id capability)

| Endpoint                                | Format     |
|-----------------------------------------|------------|
| `GET /api/audit/{task_id}/report`       | HTML       |
| `GET /api/audit/{task_id}/report.json`  | JSON       |
| `GET /api/audit/{task_id}/report.pdf`   | PDF        |
| `GET /api/audit/{task_id}/report.md`    | Markdown   |

The `task_id` is a bearer capability. When payments are enabled:
- **unknown id** → `404`
- **unpaid task** → fail-closed `402`

All formats render from the **same validated report data**, so they agree by
construction. Report retrieval never re-computes findings, never charges again,
and never exposes storage paths or secrets.

---

## 4. Pricing (USDC on Base)

Tiered by verified source size (non-blank `.sol` lines):

| Up to lines | Price       |
|-------------|-------------|
| 100         | `$0.50`     |
| 500         | `$2.50`     |
| 1,000       | `$5.00`     |
| 5,000       | `$25.00`    |
| >5,000      | custom (contact) |

- **`POST /api/audit`** is a **flat `$3.00`** and only serves contracts up to
  `REST_AUDIT_MAX_LINES` — it does not undercut the higher MCP tiers.
- **`get_source_code`** standalone: flat `$0.01`.
- Contracts above the largest tier are rejected **before any payment** with
  `ENTERPRISE_INQUIRY_REQUIRED` (never truncated or split into billable chunks).

---

## 5. Error Codes

| Code                        | HTTP | Meaning                                          |
|-----------------------------|------|--------------------------------------------------|
| `rate_limited`              | 429  | Per-IP rate limit exceeded.                      |
| `body_too_large`            | 413  | Request body over `HTTP_MAX_BODY_BYTES`.         |
| `invalid_json`              | 400  | Body is not a JSON object.                       |
| `invalid_address`           | 400  | Address failed normalization.                    |
| `source_not_verified`       | 422  | No verified source; no price can be quoted.      |
| `invalid_task_id`           | 400  | `task_id` not 1..64 chars.                       |
| `unknown_task`              | 404  | No such task (expired or never existed).         |
| `ENTERPRISE_INQUIRY_REQUIRED`| 402 | Source exceeds 5,000-line tier; custom pricing.  |
| `pricing_failed`            | 422  | Could not retrieve source for pricing.           |

---

## 6. Curl Examples

### Start an audit (x402)
```bash
curl -X POST https://x402.workfern.com/api/audit \
  -H "Content-Type: application/json" \
  -d '{"address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"}'
```
The first response is the x402 `402` challenge; pay it on Base, then re-submit
with the verified payment. On success you receive a `task_id`.

### Poll status (MCP or REST task capability)
```bash
curl https://x402.workfern.com/api/audit/<task_id>/report.json
```

### Health / discovery
```bash
curl https://x402.workfern.com/openapi.json
```

---

## 7. Report Object (JSON)

The validated `AuditReport` includes:

| Field                       | Meaning                                    |
|-----------------------------|--------------------------------------------|
| `findings[]`                | status, severity, category, SWC id, line, KB-corroborated flag |
| `summary.static_analysis_status` | `full` / `partial` / `unavailable`   |
| `summary.tools_failed`      | tools that failed (degraded, not fatal)   |
| `errors[]`                  | hard audit errors (empty = clean run)     |
| `limitations[]`             | honesty surface — what was not provable   |
| `llm_success_rate`          | fraction of valid model outputs           |

The report **never over-claims**: a reentrancy is marked `high` only when the
machine proves the CEI violation **and** history (KB) corroborates it; findings
the machine cannot independently locate are honestly marked `potential`.

---

## 8. Honesty & Payment Guarantees

- **No money moves on a failed dispatch.** Settlement happens only *after*
  the workflow dispatches successfully.
- **No double-charge.** Payments are bound to a task id; re-retrieving the
  report never charges again.
- **No silent degradation.** Missing static-analysis tools are reported in
  `tools_failed` / `limitations`, never as evidence of safety.
- **Replay-safe.** A payment payload is never accepted twice.