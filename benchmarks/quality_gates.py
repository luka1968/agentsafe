# ruff: noqa: E501 - data/report module.
"""Section 15 — commercial-readiness quality gates.

Treats the release targets as TARGETS and reports the ACTUAL measurement of
each, computed from real artifacts (the categorized benchmark suite, the
coverage model, the proxy classifier, the integrity panel, the severity
rubric). Nothing is manipulated to pass and no failure is hidden: a gate whose
target is not met is reported as not-met, with the measured value.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_BENCH = Path(__file__).resolve().parent
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import categorized_suite as S  # noqa: E402

from agentsafe.agents.integrity import build_integrity  # noqa: E402
from agentsafe.coverage import build_coverage  # noqa: E402
from agentsafe.intel.extract import extract_contract_intel  # noqa: E402
from agentsafe.intel.proxy import ProxyClass, classify_contracts  # noqa: E402
from agentsafe.schemas import Finding, FindingStatus  # noqa: E402
from agentsafe.severity import assess  # noqa: E402


def _gate(target: Any, measured: Any, passed: bool, note: str = "") -> dict[str, Any]:
    return {"target": target, "measured": measured, "passed": bool(passed), "note": note}


def _critical_high_recall(rows: list[dict[str, Any]]) -> tuple[float | None, int, int]:
    cases = {c.id: c for c in S.CASES}
    ch = []
    for row in rows:
        c = cases.get(row["id"])
        if c is None or c.kind != "vulnerable":
            continue
        if any(str(f.severity) in ("Severity.CRITICAL", "Severity.HIGH", "critical", "high")
               for f in c.candidates):
            ch.append(row)
    if not ch:
        return None, 0, 0
    hit = sum(1 for r in ch if r["predicted"])
    return hit / len(ch), hit, len(ch)


def _unsupported_proxy_count() -> int:
    """CONFIRMED/PROBABLE classifications justified ONLY by a name hint."""
    n = 0
    for case in S.CASES:
        for _path, src in case.source.items():
            intel = extract_contract_intel({_path: src})
            for cls in classify_contracts(intel):
                if cls.classification in (ProxyClass.CONFIRMED, ProxyClass.PROBABLE):
                    sig = cls.signals or {}
                    strong = (
                        sig.get("eip1967_implementation_slot")
                        or sig.get("eip1967_beacon_slot")
                        or sig.get("eip1967_admin_slot")
                        or sig.get("delegatecall")
                        or sig.get("upgrade_mechanism")
                    )
                    if not strong:
                        n += 1
    return n


def _coverage_accounting_ok() -> bool:
    cov = build_coverage(
        {"A.sol": "contract A {}", "B.sol": "contract B {}"}, {"A.sol"}
    ).to_dict()
    return all(k in cov for k in (
        "total_segments", "analyzed_segments", "unanalyzed_segments",
        "total_functions", "uncovered_functions", "is_complete",
    ))


def _failed_skipped_agents_ok() -> bool:
    # The integrity panel exposes specialist execution, failed agents and skips.
    rep = _sample_report()
    it = build_integrity(
        rep,
        scheduler_meta={"per_agent": [
            {"agent": "reentrancy", "ran": True, "errors": []},
            {"agent": "oracle", "ran": False, "skipped": "no oracle surface"},
        ]},
    )
    return (
        "specialists" in it and "failed_agents" in it and "skipped_analysis" in it
        and it["skipped_analysis"] == ["oracle"]
    )


def _sample_report() -> Any:
    from agentsafe.report import build_report
    from agentsafe.schemas import LLMUsage

    return build_report(
        address="0x" + "00" * 20, task_id="gate", is_verified_source=True,
        tool_findings=[], llm_findings=[], tools_executed=["slither"],
        tools_failed=[], tool_versions={}, llm_usage=LLMUsage(),
        limitations=[], errors=[], execution_time_seconds=1.0,
        targeted_test_results=[{"test_id": "t", "result": "not_executed"}],
        coverage={"is_complete": True, "total_segments": 1, "analyzed_segments": 1},
    )


def _severity_confidence_consistent() -> bool:
    f = Finding(title="x", severity="high", status=FindingStatus.POTENTIAL,
                source=["s"], description="d", evidence="e", confidence=0.9)
    sev, _ = assess(f)
    return (
        sev.value == "medium"                 # unproven claim capped, not inflated
        and f.status is FindingStatus.POTENTIAL  # never silently confirmed
        and f.confidence == 0.9               # confidence independent of severity
    )


def _no_fabricated_results(rows: list[dict[str, Any]]) -> tuple[bool, int]:
    rep = _sample_report()
    it = build_integrity(rep)
    honest = it["claims"]["all_tests_passed"] == "none_executed"
    fp = sum(1 for r in rows if (not r["expected"]) and r["predicted"])
    return (honest and fp == 0), fp


def _reproducible_poc() -> tuple[float, bool, str]:
    """Real EVM execution: a known-vulnerable reentrancy must be reproduced, and
    a CEI-correct control must NOT be. Returns (measured, passed, note)."""
    try:
        from agentsafe.validation.evm_poc import (
            evm_backend_available,
            run_reentrancy_poc,
            run_reentrancy_poc_safe,
        )
    except Exception as exc:
        return 0.0, False, f"poc module unavailable: {exc}"
    if not evm_backend_available():
        return (
            0.0,
            False,
            "no EVM execution backend installed (eth-tester/py-evm + solc); "
            "install the 'poc' extra to execute PoCs",
        )
    vuln = run_reentrancy_poc()
    ctrl = run_reentrancy_poc_safe()
    ok = bool(vuln.impact_demonstrated) and not bool(ctrl.impact_demonstrated)
    return (
        1.0 if ok else 0.0,
        ok,
        f"vulnerable reproduced={vuln.impact_demonstrated}, "
        f"CEI-correct control reproduced={ctrl.impact_demonstrated} "
        f"(backend eth-tester/py-evm)",
    )


def evaluate_gates() -> dict[str, Any]:
    r = S.evaluate()
    rows = r["cases"]
    agg = r["aggregate"]
    ch_recall, ch_hit, ch_n = _critical_high_recall(rows)
    unsupported = _unsupported_proxy_count()
    no_fab, fp = _no_fabricated_results(rows)
    repro, repro_passed, repro_note = _reproducible_poc()

    gates = {
        "recall_critical_high": _gate(
            ">= 0.90", round(ch_recall, 4) if ch_recall is not None else None,
            (ch_recall is not None and ch_recall >= 0.90),
            f"{ch_hit}/{ch_n} Critical/High benchmark cases detected",
        ),
        "precision_confirmed": _gate(
            ">= 0.85", agg["precision"], (agg["precision"] or 0) >= 0.85,
            "precision over predicted-positive (actionable) findings",
        ),
        "evm_rollback_false_positives": _gate(
            "== 0", sum(1 for x in rows if x["id"] == "transfer_rollback_trap"
                        and x["predicted"]),
            not any(x["id"] == "transfer_rollback_trap" and x["predicted"] for x in rows),
            "no reported EVM rollback false positive",
        ),
        "unsupported_proxy_classification": _gate(
            "== 0", unsupported, unsupported == 0,
            "no proxy classification justified only by a name/pattern",
        ),
        "coverage_accounting": _gate(
            "complete", _coverage_accounting_ok(), _coverage_accounting_ok(),
            "source + segment + function coverage recorded",
        ),
        "failed_skipped_agent_handling": _gate(
            "explicit", _failed_skipped_agents_ok(), _failed_skipped_agents_ok(),
            "failed agents and skipped analysis are recorded explicitly",
        ),
        "reproducible_poc": _gate(
            ">= 1 executed PoC reproducing impact (and none on a CEI-correct control)",
            repro, repro_passed, repro_note,
        ),
        "no_fabricated_results": _gate(
            "== 0 fabricated", fp, no_fab,
            "dynamic tests honestly 'none_executed'; no fabricated pass",
        ),
        "severity_confidence_consistency": _gate(
            "separate + capped", _severity_confidence_consistent(),
            _severity_confidence_consistent(),
            "severity != confidence != verification status; unproven capped",
        ),
    }
    met = sum(1 for g in gates.values() if g["passed"])
    return {
        "gates": gates,
        "summary": {
            "n_gates": len(gates),
            "n_met": met,
            "n_not_met": len(gates) - met,
            "commercially_ready": met == len(gates),
        },
    }


if __name__ == "__main__":  # pragma: no cover - manual reporting
    import json

    print(json.dumps(evaluate_gates(), indent=2))
