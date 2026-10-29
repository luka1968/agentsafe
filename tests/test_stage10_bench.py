"""Stage 10 — validation benchmark + regression evaluation tests.

Locks the regression guards so the benchmark cannot silently regress:
  - CEI-compliant reentrancy claims are never confirmed
  - theoretical overflow (no attack path) is never confirmed, even with a
    detector flag (a detector hit is not exploitability)
  - tool-corroborated real CEI violations still confirm
  - benchmark run is deterministic and writes the JSON artifact
"""

from __future__ import annotations

import json
import sys

import pytest

from agentsafe.agents.validation import ValidationAgent
from agentsafe.schemas import Finding, FindingStatus, Severity

# benchmarks/ is not a package; import by path
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent / "benchmarks"))
import validation_bench as vb  # noqa: E402


def _mk(title, severity, evidence, src_path, line_start,
        status=FindingStatus.LLM_SUGGESTED, **kw) -> Finding:
    return Finding(
        title=title, severity=severity, status=status,
        source=kw.pop("source", ["agent"]),
        description=kw.pop("description", title),
        evidence=evidence, file_path=src_path, line_start=line_start, **kw)


class TestBenchmarkDeterminism:
    def test_run_is_reproducible(self):
        a = vb.run_bench()
        b = vb.run_bench()
        assert a["accuracy"] == b["accuracy"]
        assert a["rows"] == b["rows"]

    def test_artifact_written(self):
        out = vb.OUT_DIR / "validation_bench.json"
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["accuracy"] == vb.run_bench()["accuracy"]
        assert "per_class" in data and "regression" in data

    def test_all_cases_correct(self):
        res = vb.run_bench()
        assert res["accuracy"] == 1.0
        assert res["false_positive_rate"] == 0.0


class TestRegressionGuards:
    """Independent of the benchmark harness: re-assert the invariants that
    Stage 10 exists to protect."""

    def test_cei_compliant_reentrancy_never_confirmed(self):
        v = ValidationAgent()
        f = _mk("Reentrancy in withdraw", Severity.HIGH,
                "payable(msg.sender).transfer(amount);", "Vault.sol", 3)
        out = v.validate([f], [], {"Vault.sol": vb.CEI_SRC})
        assert out.findings[0].status is FindingStatus.REJECTED

    def test_theoretical_overflow_never_confirmed_even_with_detector(self):
        """A detector flag on an arithmetic op with no concrete attack path is
        informational — tool hits corroborate a *claim*, not exploitability."""
        v = ValidationAgent()
        f = _mk("Integer overflow in addition", Severity.HIGH,
                "balances[a] += x;", "Vault.sol", 5)
        tool = _mk("arithmetic", Severity.MEDIUM, "x", "Vault.sol", 5,
                   status=FindingStatus.TOOL_DETECTED, source=["slither"],
                   detector_id="arithmetic")
        out = v.validate([f], [tool], {"Vault.sol": vb.CEI_SRC})
        assert out.findings[0].status is FindingStatus.INFORMATIONAL

    def test_real_cei_violation_with_tool_confirms(self):
        v = ValidationAgent()
        f = _mk("Reentrancy: external call before state update", Severity.HIGH,
                "payable(msg.sender).transfer(amount);", "Vault.sol", 2)
        tool = _mk("reentrancy-eth", Severity.HIGH, "call", "Vault.sol", 2,
                   status=FindingStatus.TOOL_DETECTED, source=["slither"],
                   detector_id="reentrancy-eth")
        out = v.validate([f], [tool], {"Vault.sol": vb.NON_CEI_SRC})
        assert out.findings[0].status is FindingStatus.CONFIRMED

    def test_overflow_with_real_path_confirms(self):
        """An overflow with attacker-controlled input AND demonstrated impact
        must still confirm — the calibration must not suppress real bugs."""
        v = ValidationAgent()
        f = Finding(
            title="Integer overflow in addition", severity=Severity.CRITICAL,
            status=FindingStatus.LLM_SUGGESTED, source=["agent"],
            description=(
                "attacker-controlled `amount` is added to `total` without an "
                "overflow check; wrapping lets the attacker drain the vault"),
            evidence="balances[a] += x;", file_path="Vault.sol", line_start=5)
        tool = _mk("arithmetic", Severity.HIGH, "x", "Vault.sol", 5,
                   status=FindingStatus.TOOL_DETECTED, source=["slither"],
                   detector_id="arithmetic")
        out = v.validate([f], [tool], {"Vault.sol": vb.CEI_SRC})
        assert out.findings[0].status is FindingStatus.CONFIRMED
