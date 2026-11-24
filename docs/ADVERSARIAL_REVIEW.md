# Independent Adversarial Review

A finding is a *hypothesis* until something outside the agent that proposed it
tries to disprove it. AgentSafe's specialist agents **propose**; the
`ValidationAgent` **classifies**; the adversarial review **refutes**.

This stage exists because the dominant production false positives were not
subtle logic errors — they were claims that the code itself contradicts
(`docs/baseline.md`): internal-only functions reported as externally
reachable, "missing access control" on paths that are authorization-gated, a
state-mutation claim pinned on a `view` function, and standard proxy-library
behaviour read as a defect.

## Where it sits

```
fetch → classify → static tools → contract intel → specialist agents
      → validation (state machine) → ADVERSARIAL REVIEW → severity → report
```

It runs as its own pipeline stage (`adversarial_review`) on every finding that
survived validation. Its results are recorded per finding
(`metadata.challenge`), in `contradicting_evidence`, and summarised in
`report.adversarial_review`.

## The one rule that matters

**The engine can only reduce a finding's standing, never raise it.** It never
introduces a finding, never confirms one, and never claims a contract is safe.
A finding it cannot assess is left exactly as it was.

## Rules

| rule | verdict | what it refutes |
|---|---|---|
| `ro0_readonly_contradiction` | rejected | a state-mutation / privileged-action claim whose located function is declared `view`/`pure` — a view function cannot mutate state |
| `ra0_internal_unreachable` | informational | an exploit claim in an internal/private function that no external entry point reaches — an attacker cannot invoke it |
| `ac0_authz_gated_path` | informational | "missing access control" where **every** external path to the function passes an authorization gate |
| `pxy0_proxy_admin_by_design` | informational | upgrade/admin control claims on a recognized proxy whose upgrade authorization is enforced by a guarded `_authorizeUpgrade` or a transparent-proxy admin gate |
| `vnd0_vendored_standard` | informational | standard-semantics claims about vendored third-party library code (out of the audited surface) |

## How the reachability model stays honest

The model (`agentsafe/agents/reachability.py`) is built from the same verified
source the agents saw, through the canonical contract-intel extractor. It
answers a single question with a **tri-state** result — `reachable`,
`not_reachable`, `unknown`:

- `not_reachable` is returned **only** when every condition holds: the function
  is explicitly `internal`/`private`, it is not reached from any external entry
  point, its contract is concrete (not abstract/interface), and the file has no
  unparsed `receive()`/`fallback()` body that could call it.
- Any ambiguity — an unresolvable location, pseudo-source, an abstract base, a
  fallback body — yields `unknown`, and **no verdict is drawn from `unknown`**.

For "missing access control", the model computes *attacker reachability*: an
external path through the call graph that never **enters** an
authorization-guarded function. A function that is reachable but not
attacker-reachable is gated on every path, so the missing-control claim is
contradicted. A genuinely open external function is attacker-reachable and is
**never** suppressed — clearing a real bug would be a missed vulnerability.

## Scope and limits (explicit)

- Deterministic only. No LLM is asked whether a finding is real; refutation is
  a source-level fact (reachability, authorization, mutability, scope), not an
  opinion.
- Conservative by construction. Ambiguity resolves to *no action*, never to a
  refutation. The asymmetry is deliberate: it is better to leave a false
  positive for a human than to silently clear a true one.
- Downgrades are preserved for auditability (rejected/informational findings
  stay in the report with the rule, the reason and the contradicting source
  line), so nothing is hidden — only moved out of the severity headline.
- Pseudo-source (closed-source) audits get no reachability verdicts: the
  structure is not reliable enough to refute on.

## Reproduce

```
pytest tests/test_adversarial_fp.py
```

The suite encodes each documented false positive and its correct disposition,
plus the negative cases (an open external function and an unguarded
`_authorizeUpgrade` that must **not** be suppressed).

## Verdict ladder (Section 8)

Every candidate ends in exactly one explicit state. A candidate may be
downgraded by the challenge but is **never silently upgraded** to `confirmed`,
and rejected findings are kept in the report (excluded only from severity
headlines):

| Verdict | Meaning |
|---|---|
| `confirmed` | reproducible execution **or** strong, independently checked technical evidence (tool + LLM agreement at the same location, or deterministic corroboration) |
| `high_confidence` | strongly supported by independent evidence (independent historical KB case or a deterministic rule), but full reproduction is unavailable |
| `potential` | plausible; exploitability or important preconditions remain unverified |
| `informational` | security-relevant observation without a demonstrated exploitable vulnerability |
| `rejected` | contradicted by deterministic source analysis, or missing required evidence |
| `unverified` | evidence is insufficient to reach a reliable conclusion |
| `needs_manual_review` | validation inconclusive; a human decision is required |

## Independent challenge (Step 2) and reconciliation (Step 3)

The challenge actively looks for a reason the claim is **wrong**: unreachable
code (`ra0_internal_unreachable`), authorization gates on every path
(`ac0_authz_gated_path`), a mutation claim pinned on a `view`/`pure` function
(`ro0_readonly_contradiction`), an existing reentrancy guard
(`pr0_existing_guard`), standard proxy design (`pxy0_proxy_admin_by_design`),
vendored-library scope (`vnd0_vendored_standard`), declaration-only evidence
(`iface0_declaration_only_evidence` → `unverified`), and an infeasible attacker
model (`att0_infeasible_attacker_model` — unreachable code, unavailable
permissions, or a claim that assumes an absent external contract's behavior).

It never rewrites or rubber-stamps the original explanation. When discovery and
challenge disagree, **both arguments are preserved** on the finding
(`metadata.reconciliation.discovery` and `.challenge`) with the resolution
basis recorded (`resolved_by: deterministic source analysis … no majority
vote`); the disagreement is settled by source evidence only, never by vote.

## Executable verification (PoC) and its limits

When a candidate can be reproduced, we build a deterministic **PoC plan**
(`agents/poc.py`): the realistic attacker, preconditions, concrete transaction
sequence, expected state transition, and the **impact predicate** that must hold
to prove impact. High-impact / financially-significant findings are prioritised.

A PoC run is classified into exactly one honest outcome:

| Outcome | Meaning |
|---|---|
| `successful_exploitation` | execution reproduced the vulnerable state **and** the impact assertion held |
| `expected_revert` | the call reverted as an existing protection dictates (attack blocked) |
| `failed_attack` | execution ran but did not reproduce the claimed impact |
| `inconclusive` | execution could not be interpreted, or a pass **without** a demonstrated impact (a compiling/passing PoC is **not** proof) |
| `environment_limitation` | no execution backend is available; the plan is retained and **no result is claimed** |

**Environment reality:** this deployment has no EVM execution backend (no
Foundry `forge`, `anvil`, `cast`, `solc`, `geth`/`evm`, and no
`py-evm`/`eth-tester`/`revm`; `solc-select` cannot fetch a compiler offline).
Foundry detection rejects the unrelated npm `forge` shim. Consequently PoC work
here reports `environment_limitation`, records the plan on the finding
(`metadata.poc`), adds an explicit limitation, and **never fabricates a
result** — the finding's confidence is left exactly as validated. The existing
Stage-8 targeted-test harness reports `not_executed` under the same rule.

## Deployment and compiler context (Section 11)

The same finding means different things depending on *what* is audited and *how*
it is deployed. A deterministic **deployment context** (`agents/deployment.py`)
is built from verified-source status, the evidence-based proxy classification,
and the compiler version, and recorded on every finding (`metadata.deployment`)
and at the top level (`report.deployment`):

- **Source kind** — `deployed_verified_source` vs `deployed_unverified_bytecode`.
- **Immutability** — `immutable` (no proxy evidence) vs `upgradeable`
  (CONFIRMED/PROBABLE proxy) vs `unknown`; plus
  `remediation_applicable_to_bytecode` (true only for an upgradeable verified
  contract).
- **Compiler era** — the actual `solc_mm` and a `pre_0_8` flag. Pre-0.8
  unchecked arithmetic is **not** automatically exploitable; a concrete,
  reachable attack path is required, and version-only claims are informational
  (the `ov0` rule already enforces this).
- **Disposition** (`metadata.disposition`) — `existing_exposure`,
  `informational_observation`, or
  `recommendation_not_applicable_to_deployed_bytecode`.

Compiler warnings and code-quality observations are never promoted to
actionable vulnerabilities: a code-quality / compiler-warning finding, or a
best-practice recommendation on an **immutable deployed** contract whose
remediation cannot be applied to the deployed bytecode, is reclassified
**informational** (kept in the report, removed from the severity headline) with
the reason recorded.

## Finding quality and severity (Section 12)

Every reported finding carries the full required evidence package (19 elements):
title, severity, verdict, classification (SWC/CWE/category), exact location,
vulnerable code, root cause, attacker model, preconditions, concrete attack
sequence, state transitions, impact, exploitability, supporting evidence,
counterarguments considered, validation outcome, PoC status, remediation, and
confidence. `agents/quality.py` audits the package deterministically
(`metadata.quality` + a report limitation naming any gap) and guarantees a PoC
status for every actionable finding — **presence only; nothing is invented and
no finding is padded**.

Severity is kept **separate** from confidence and verification status. Severity
is assigned by the documented rubric from realistic impact and exploitability
(`ov0`/`pt0` cap unproven claims; `informational` for standard/theoretical
cases), and a **HIGH severity `potential` finding is capped and never becomes a
confirmed HIGH** — the claim is preserved (`proposed_severity`) while the
reported severity reflects the evidence. Ordinary compiler warnings, style
issues, and theoretical edge cases are never labelled exploitable
vulnerabilities.

## Report integrity and customer trust (Section 13)

Every report carries a consolidated **Audit integrity** panel
(`report.integrity`, `agents/integrity.py`), rendered in HTML and Markdown:

- audit completion status; source files **received vs analyzed**; segment and
  function **coverage**; static-engine execution status; **specialist
  execution**, failed agents and skipped analysis; **dynamic verification** and
  **PoC** status; the **verified-vs-suspected** count split; and the important
  limitations.

It carries an explicit **claims guard** that can only tell the truth:

- `full_coverage` is true only when coverage is complete **and** the audit state
  is complete;
- `all_tests_passed` is `none_executed` when no dynamic test ran — never a
  fabricated "passed";
- `reproduced` counts **only** findings whose executed test/PoC demonstrated the
  impact; an LLM hypothesis is never counted as reproduced.

Confirmed findings receive **specific, code-anchored remediation**
(`agents/remediation.py`): when a deterministic rule identified the mechanism
(e.g. a CEI violation) the remediation names the function, location and the
exact statement to fix, instead of generic hardening advice; when nothing
specific can be derived it is not invented.




