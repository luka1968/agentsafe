"""Phase 3 — structured vulnerability intelligence (additive projection).

Produces one coherent, honestly-partial structure per record so agents can
reason over identification / root-cause / exploit / verification / remediation
fields without re-deriving them from prose. The projection is DERIVED from the
record's existing columns — it never invents technical detail, and a fact the
record does not carry is emitted as ``None`` (or ``[]``) rather than guessed.
It is stored in the additive ``structured_intel`` jsonb column; the underlying
columns remain the single source of truth, so nothing is lost or shadowed and
the projection can be regenerated (or dropped) at will.

Sections (stable keys; a missing value is null):
  identification      record id, title, category, cwe/swc, severity, source
  root_cause          root cause, code pattern, function/contract, state, calls
  exploit_intelligence entry, attacker model/permissions, preconditions,
                      sequence, ordering, transitions, capital, deps, impact
  verification        PoC, test env, reproduction result, evidence,
                      counterexamples, known protections, validation notes
  remediation         fix, code changes, security patterns, related records
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("agentSAFE.knowledge.structured")

# Documented shape: section -> ordered field names. Used for coverage reporting
# and to keep the emitted object stable even when values are missing.
SCHEMA: dict[str, tuple[str, ...]] = {
    "identification": (
        "record_id", "external_record_id", "title", "category", "subcategory",
        "cwe_id", "swc_id", "severity", "source_id", "source_reference",
        "validation_status", "quality_status", "claim_status"),
    "root_cause": (
        "root_cause", "vulnerable_code_pattern", "affected_function",
        "affected_contract", "state_variables", "external_interactions",
        "solc_version", "evm_semantics"),
    "exploit_intelligence": (
        "attack_entry", "attacker_model", "required_permissions",
        "preconditions", "attack_sequence", "call_sequence",
        "transaction_ordering", "tx_conditions", "state_transitions",
        "state_dependencies", "required_capital", "external_dependencies",
        "exploitability_conditions", "impact"),
    "verification": (
        "proof_of_concept", "test_environment", "reproduction_result",
        "evidence_references", "counterexamples", "known_protections",
        "validation_notes"),
    "remediation": (
        "root_cause_remediation", "recommended_code_changes",
        "security_patterns", "related_records"),
}


def _clean(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s or None
    if isinstance(v, (list, tuple)):
        items = [x for x in v if x not in (None, "")]
        return items or None
    if isinstance(v, dict):
        return v or None
    return v


def _first(*vals: Any) -> Any:
    for v in vals:
        c = _clean(v)
        if c is not None:
            return c
    return None


def _join_lists(*vals: Any) -> list | None:
    out: list = []
    for v in vals:
        c = _clean(v)
        if isinstance(c, list):
            out.extend(c)
        elif c is not None:
            out.append(c)
    return out or None


def source_reference(record: dict[str, Any]) -> str | None:
    """Best AVAILABLE reference for the record — never fabricated: the URL if
    present, else the platform:contest:issue id, else the external id."""
    url = _clean(record.get("source_url")) or _clean(record.get("url"))
    if url:
        return url
    ext = _clean(record.get("external_record_id"))
    md = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    contest = _clean(md.get("contest"))
    issue = _clean(md.get("issue_id"))
    platform = _clean(md.get("source_platform")) or _clean(record.get("source_id"))
    if platform and contest and issue:
        return f"{platform}:{contest}:{issue}"
    return ext


def build_structured_intel(record: dict[str, Any]) -> dict[str, Any]:
    preconditions = _clean(record.get("preconditions"))
    tx_conditions = _clean(record.get("tx_conditions"))
    ident = {
        "record_id": _first(record.get("id")),
        "external_record_id": _first(record.get("external_record_id")),
        "title": _first(record.get("title")),
        "category": _first(record.get("category")),
        "subcategory": _first(record.get("subcategory")),
        # CWE is only set when the record actually carries one; never inferred
        # from SWC or category.
        "cwe_id": _first(record.get("cwe_id")),
        "swc_id": _first(record.get("swc_id")),
        "severity": _first(record.get("severity")),
        "source_id": _first(record.get("source_id") or record.get("source")),
        "source_reference": source_reference(record),
        "validation_status": _first(record.get("verification_status")),
        "quality_status": _first(record.get("quality_status")),
        "claim_status": _first(record.get("quality_claim")),
    }
    root = {
        "root_cause": _first(record.get("root_cause")),
        "vulnerable_code_pattern": _first(record.get("vulnerable_code")),
        "affected_function": _first(record.get("affected_function")),
        "affected_contract": _first(record.get("affected_contract")),
        "state_variables": _clean(record.get("state_vars")),
        "external_interactions": _join_lists(record.get("external_calls"),
                                             record.get("internal_calls")),
        "solc_version": _first(record.get("solc_version")),
        # No backing column exists for EVM-semantics notes yet: emitted null
        # (honest) rather than inferred.
        "evm_semantics": _first(record.get("evm_semantics")),
    }
    exploit = {
        "attack_entry": _first(record.get("attack_entry")),
        "attacker_model": _first(record.get("attacker_model")),
        "required_permissions": _clean(record.get("attacker_permissions")),
        "preconditions": preconditions,
        "attack_sequence": _first(record.get("attack_scenario"),
                                  record.get("exploit_sequence")),
        "call_sequence": _clean(record.get("call_sequence")),
        "transaction_ordering": _first(record.get("tx_ordering")),
        "tx_conditions": tx_conditions,
        "state_transitions": _first(record.get("state_transitions")),
        "state_dependencies": _clean(record.get("state_deps")),
        "required_capital": _first(record.get("required_capital")),
        "external_dependencies": _clean(record.get("cross_contract_deps")),
        # Exploitability conditions = the record's own preconditions + tx
        # conditions (the facts that make the bug exploitable). Never invented.
        "exploitability_conditions": _join_lists(preconditions, tx_conditions),
        "impact": _first(record.get("impact")),
    }
    verification = {
        "proof_of_concept": _first(record.get("poc_code"),
                                   record.get("poc_reference")),
        "test_environment": _first(record.get("test_setup"),
                                   record.get("test_tooling")),
        "reproduction_result": _first(record.get("test_result")),
        "evidence_references": _first(record.get("verification_evidence"),
                                      record.get("poc_reference")),
        "counterexamples": _first(record.get("fp_patterns"),
                                  record.get("refutation_signals")),
        "known_protections": _first(record.get("security_pattern"),
                                    record.get("safe_code"),
                                    record.get("known_limitations")),
        "validation_notes": _first(record.get("validation_notes")),
    }
    remediation = {
        "root_cause_remediation": _first(record.get("remediation")),
        "recommended_code_changes": _first(record.get("corrected_code")),
        "security_patterns": _first(record.get("security_pattern")),
        "related_records": _first(record.get("related_record_ids"),
                                  record.get("related_vuln_classes")),
    }
    return {
        "identification": ident,
        "root_cause": root,
        "exploit_intelligence": exploit,
        "verification": verification,
        "remediation": remediation,
    }


def coverage(intel: dict[str, Any]) -> dict[str, Counter]:
    """Count populated (non-null, non-empty) fields per section."""
    counts: dict[str, Counter] = {}
    for section, fields in SCHEMA.items():
        c: Counter = Counter()
        for f in fields:
            if _clean(intel.get(section, {}).get(f)) is not None:
                c["filled"] += 1
            c["total"] += 1
        counts[section] = c
    return counts


# ---------------------------------------------------------------------------
# store pass
# ---------------------------------------------------------------------------
_FETCH = """
    SELECT id, source_id, external_record_id, title, description, category,
           subcategory, severity, cwe_id, swc_id, verification_status,
           quality_status, quality_claim, source_url, metadata,
           root_cause, vulnerable_code, corrected_code, affected_function,
           affected_contract, state_vars, external_calls, internal_calls,
           solc_version, attack_entry, attacker_permissions, preconditions,
           attack_scenario, exploit_sequence, call_sequence, tx_conditions,
           state_deps, cross_contract_deps, impact, poc_code, poc_reference,
           test_setup, test_tooling, test_result, verification_evidence,
           fp_patterns, refutation_signals, security_pattern, safe_code,
           known_limitations, remediation, related_vuln_classes
    FROM vulnerability_knowledge
    ORDER BY id
"""

_POPULATED = (
    "title", "category", "severity", "root_cause", "attack_entry",
    "preconditions", "attack_scenario", "impact", "remediation",
    "vulnerable_code", "affected_function", "affected_contract",
)


@dataclass
class StructureSummary:
    scanned: int = 0
    written: int = 0
    field_fill: dict[str, int] = field(default_factory=dict)
    section_fill: dict[str, dict[str, int]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned, "written": self.written,
            "section_fill": self.section_fill,
            "field_fill": dict(sorted(self.field_fill.items(),
                                      key=lambda kv: -kv[1])),
            "errors": self.errors[:20],
        }


def structure_store(store: Any, *, limit: int | None = None) -> StructureSummary:
    """Project every record into ``structured_intel``. Deterministic and
    idempotent; the source columns are never modified."""
    sql = _FETCH + (" LIMIT %s" if limit else "")
    with store._connect() as conn, conn.cursor() as cur:
        cur.execute(sql, (int(limit),) if limit else ())
        rows = [dict(r) for r in cur.fetchall()]

    summary = StructureSummary(scanned=len(rows))
    sec_totals: dict[str, dict[str, int]] = {
        s: {"filled": 0, "total": 0} for s in SCHEMA}
    updates: list[tuple[str, int]] = []
    for row in rows:
        try:
            intel = build_structured_intel(row)
        except Exception as exc:  # one bad row never stops the pass
            summary.errors.append(f"row {row.get('id')}: {exc}")
            continue
        for section, c in coverage(intel).items():
            sec_totals[section]["filled"] += c["filled"]
            sec_totals[section]["total"] += c["total"]
        for f in _POPULATED:
            if _clean(row.get(f)) is not None:
                summary.field_fill[f] = summary.field_fill.get(f, 0) + 1
        updates.append((json.dumps(intel), row["id"]))

    for i in range(0, len(updates), 200):
        batch = updates[i:i + 200]
        try:
            with store._connect() as conn, conn.cursor() as cur:
                cur.executemany(
                    "UPDATE vulnerability_knowledge SET structured_intel = "
                    "%s::jsonb WHERE id = %s", batch)
            summary.written += len(batch)
        except Exception as exc:  # noqa: BLE001 - rerun finishes (idempotent)
            summary.errors.append(f"batch {i // 200}: {exc}")
    summary.section_fill = {
        s: {"filled": v["filled"], "total": v["total"],
            "pct": round(100 * v["filled"] / v["total"], 1) if v["total"] else 0.0}
        for s, v in sec_totals.items()}
    from agentsafe.metrics import get_metrics

    get_metrics().incr("structured_intel_written", summary.written)
    return summary
