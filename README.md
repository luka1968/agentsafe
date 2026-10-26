# AgentSafe — AI-Powered Smart Contract Security Intelligence

[![x402 Pay-per-call](https://img.shields.io/badge/Payment-x402%20USDC%20on%20Base-00D395?style=flat-square&logo=ethereum)](https://www.x402scan.com)
[![Network: Ethereum Mainnet](https://img.shields.io/badge/Network-Ethereum%20Mainnet-3C3C3D?style=flat-square&logo=ethereum)](https://ethereum.org)
[![MCP Server](https://img.shields.io/badge/Protocol-MCP-5B5BD6?style=flat-square)](https://modelcontextprotocol.io)

Secure your Web3 journey with **intelligent vulnerability detection**,
**multi-engine security analysis**, and **actionable risk insights**. AgentSafe
combines advanced AI reasoning with industry-leading security tools to help
developers and AI agents identify potential vulnerabilities in Ethereum smart
contracts.

Seamlessly integrated with **MCP** and powered by **x402 pay-per-use USDC
micropayments on Base**.

> 🔒 **Security Notice**: AgentSafe provides AI-assisted security assessments.
> Results are informational, require independent verification, and do not
> replace a professional security audit.

## Highlights
- 🔍 **Closure-source / deep-logic analysis** — send any `0x` contract address
- ⚡ **x402 pay-per-call** — pay in USDC on Base, no subscription, no lock-in
- 🧵 **Streamable HTTP** MCP transport — stateless & serverless-friendly
- 🛡️ **Fail-closed** — payment verified on-chain before any audit is dispatched
- ☁️ **Serverless persistent** — task state survives cold starts (Upstash Redis)

## Validation Engine
Every candidate finding passes a deterministic validation pipeline before it
reaches the report:
- **5-state machine** — `confirmed` (independent dual-source corroboration only),
  `potential` (default exit), `informational` (standard behavior / theoretical),
  `rejected` (deterministically refuted, e.g. Checks-Effects-Interactions verified
  in source), `needs_manual_review` (evidence untraceable — hallucination guard).
  Entry states (`tool_detected`/`llm_suggested`) never appear in final reports.
- **Anti-hallucination gate** — LLM findings must carry an evidence quote that is
  located verbatim in the analyzed source, with line numbers; otherwise they are
  downgraded for manual review, never presented as fact.
- **Evidence-based severity rubric** — severity is assessed from exploit
  prerequisites and mitigating controls, never from LLM confidence or repetition:
  unvalidated claims are capped at medium (the original claim is preserved in
  `proposed_severity`), confirmed findings may only be downgraded (privilege
  gates, pausable/timelock/guard controls), never upgraded.
- **Full audit trail** — every state change records the rule that fired
  (`re0_cei_satisfied`, `ov0_theoretical_only`, `cr0_independent_support`, …),
  the reason, and supporting/contradicting code references with line numbers.

> AgentSafe delivers AI-assisted security assessment with deterministic
> falsification — informational by design, not a substitute for a formal audit.

## Pay-per-call Pricing
| Tier | Price | Scope |
|------|-------|-------|
| MCP audit | $0.50 / $2.50 / $5.00 / $25.00 | by contract size |
| REST audit (`POST /api/audit`) | $3.00 flat | ≤ 500 source lines |

## Connect (MCP client)
- **Endpoint**: `https://x402.workfern.com/mcp`
- **Transport**: Streamable HTTP (JSON responses)
- `initialize` is free; tool calls trigger an x402 payment in USDC on Base.

## REST API
```bash
curl -X POST https://x402.workfern.com/api/audit \
  -H "content-type: application/json" \
  -d '{"address":"0xdAC17F958D2ee523a2206206994597C13D831ec7"}'
# -> 402 + PAYMENT-REQUIRED header (x402 v2) with exact on-chain payment terms
```
OpenAPI spec: `https://x402.workfern.com/openapi.json`

## Topics
`#SmartContractAudit` `#Web3Security` `#MCP` `#Ethereum` `#x402` `#AISecurity` `#Solidity`

## Refund policy
https://x402.workfern.com/refund
