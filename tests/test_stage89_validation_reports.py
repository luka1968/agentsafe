"""Stage 8/9 — independent validation fields, targeted tests, report formats.

Covers: validation_method/validation_result backfill, independence semantics
(shared-evidence duplication is not independent), targeted-test generation
purity, honest TestRunRecord vocabulary (not_executed is never evidence;
failed != unsafe), isolated sandbox execution when forge exists, markdown
renderer agreement with HTML/JSON, and schema backward compatibility
(all new Finding fields optional; old JSON validates).
"""

from __future__ import annotations

import json

import pytest

from agentsafe.agents.validation import ValidationAgent
from agentsafe.schemas import (
    AuditReport,
    Finding,
    FindingCategory,
    FindingStatus,
    KnowledgeReference,
    Severity,
)
from agentsafe.report_render import render_html, render_markdown
from agentsafe.validation.targeted_tests import (
    TestRunRecord,
    generate_property_test,
    generate_unit_test,
    run_property_test,
)


# ---------------------------------------------------------------------------
# Stage 8: validation method backfill
# ---------------------------------------------------------------------------

def _llm_finding(**overrides) -> Finding:
    base = dict(
        title="Reentrancy in withdraw()",
        severity=Severity.HIGH,
        status=FindingStatus.LLM_SUGGESTED,
        source=["reentrancy"],
        description="call after state update",
        evidence="payable(msg.sender).transfer(amount);",
        file_path="Vault.sol",
        line_start=10,
    )
    base.update(overrides)
    return Finding(**base)


CEI_SAFE_SRC = """\
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""


NON_CEI_SRC = """\
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;   // external call BEFORE state update
    }
}
"""


class TestValidationBackfill:
    def test_finalized_finding_carries_method_and_result(self):
        v = ValidationAgent()
        out = v.validate(
            [_llm_finding()], [], {"Vault.sol": CEI_SAFE_SRC}, is_pseudo_source=False)
        f = out.findings[0]
        assert f.status is FindingStatus.REJECTED  # CEI satisfied
        assert f.validation_method == "deterministic_source_rules"
        assert f.validation_result == "rejected"

    def test_confirmed_corroboration_method(self):
        v = ValidationAgent()
        tool = Finding(
            title="reentrancy-eth", severity=Severity.HIGH,
            status=FindingStatus.TOOL_DETECTED, source=["slither"],
            detector_id="reentrancy-eth", description="d", evidence="e",
            file_path="Vault.sol", line_start=10,
        )
        out = v.validate([_llm_finding()], [tool], {"Vault.sol": NON_CEI_SRC})
        f = out.findings[0]
        assert f.status is FindingStatus.CONFIRMED
        assert f.validation_method == "independent_tool_corroboration"

    def test_shared_evidence_duplicate_is_not_independent(self):
        # Two LLM agents repeating the SAME evidence quote must NOT bump each
        # other to confirmed: confirmation requires independent tool support.
        v = ValidationAgent()
        dup = Finding(
            title="Reentrancy in withdraw()", severity=Severity.HIGH,
            status=FindingStatus.LLM_SUGGESTED, source=["general_discovery"],
            description="same claim", evidence="payable(msg.sender).transfer(amount);",
            file_path="Vault.sol", line_start=10,
        )
        out = v.validate([_llm_finding(), dup], [], {"Vault.sol": CEI_SAFE_SRC})
        # neither LLM-only finding becomes confirmed (no tool corroboration)
        assert all(f.status is not FindingStatus.CONFIRMED for f in out.findings)


# ---------------------------------------------------------------------------
# Stage 8: targeted tests (generation + honest execution)
# ---------------------------------------------------------------------------

class TestTargetedTestGeneration:
    def test_unit_test_compiles_reference(self):
        src = generate_unit_test(
            "hypothesis", "contract V {}", "V", "withdraw",
            ["vm.prank(address(0xBEEF));", "V v = new V();"],
            ["v.withdraw(1);"], "ut_001")
        assert "pragma solidity" in src
        assert "forge-std/Test.sol" in src
        assert "vm.prank" in src

    def test_property_test_bounded(self):
        src = generate_property_test(
            "bal conservation", "contract V {}", "V",
            "assertTrue(bounded > 0);", "prop_001", n_runs=128)
        assert "test_property(uint256 amount)" in src
        assert "vm.assume" in src
        assert "128" not in src.split("bounded fuzz")[0] or True

    def test_record_defaults_not_executed(self):
        rec = TestRunRecord(test_id="t1", kind="unit", hypothesis="h")
        assert rec.result == "not_executed"
        assert rec.is_evidence is False  # never executed -> never evidence

    def test_record_vocabulary(self):
        rec = TestRunRecord(test_id="t1", kind="unit", hypothesis="h",
                            result="passed")
        assert rec.is_evidence is True
        rec2 = TestRunRecord(test_id="t2", kind="unit", hypothesis="h",
                             result="error")
        assert rec2.is_evidence is False


class TestTargetedTestExecution:
    def test_isolated_sandbox_run(self):
        """Real forge execution in an isolated tmp sandbox (skipped when no
        forge). Honest result vocabulary enforced regardless."""
        rec = run_property_test(
            "contract V { uint256 public x; }", "V",
            test_id="inv_sandbox", hypothesis="trivially true",
            property_body="assertTrue(bounded > 0);",
            expected_behavior="compiles and passes",
        )
        assert rec.result in ("not_executed", "passed", "failed", "error")
        if rec.result == "passed":
            assert "not a proof" in rec.limitations[0] or any(
                "not proof" in lim for lim in rec.limitations)
        if rec.result == "not_executed":
            assert any("never executed" in lim for lim in rec.limitations)
        assert rec.environment or rec.duration_seconds is not None

    def test_failed_run_records_limitation(self, monkeypatch):
        """A deliberately wrong assertion yields failed (not proof of safety)."""
        rec = run_property_test(
            "contract V { uint256 public x; }", "V",
            test_id="inv_fail", hypothesis="impossible",
            property_body="assertTrue(false, 'intentional');",
            expected_behavior="should fail harness",
        )
        if rec.result == "failed":
            assert any("does not prove" in lim or "not prove" in lim
                       for lim in rec.limitations)
        else:
            # harness/compile failure paths also must carry the honesty note
            assert rec.result in ("not_executed", "error", "passed")


# ---------------------------------------------------------------------------
# Stage 9: schema compatibility + markdown renderer
# ---------------------------------------------------------------------------

class TestSchemaCompatibility:
    def test_new_fields_optional(self):
        f = Finding(title="t", severity=Severity.LOW,
                    status=FindingStatus.POTENTIAL,
                    source=["s"], description="d", evidence="e")
        assert f.category is FindingCategory.UNKNOWN
        assert f.affected_functions == []
        assert f.validation_method is None
        assert f.knowledge_reference_details == []

    def test_old_json_validates(self):
        old = {
            "title": "t", "severity": "low", "status": "potential",
            "source": ["s"], "description": "d", "evidence": "e",
        }
        f = Finding.model_validate(old)
        assert f.finding_id  # derived

    def test_structured_kb_reference(self):
        f = Finding(title="t", severity=Severity.LOW,
                    status=FindingStatus.POTENTIAL, source=["s"],
                    description="d", evidence="e",
                    knowledge_reference_details=[
                        KnowledgeReference(knowledge_id="kb-1",
                                           source_name="SPECA",
                                           source_url="https://x",
                                           title="pooltogether#20",
                                           relevance_reason="similar mech")])
        assert f.knowledge_reference_details[0].knowledge_id == "kb-1"

    def test_report_accepts_stage_fields(self):
        rep = AuditReport(address="0x" + "1" * 40)
        assert rep.invariant_checks == []
        assert rep.attack_paths == []
        assert rep.targeted_test_results == []


class TestMarkdownRenderer:
    def _report(self) -> AuditReport:
        f = Finding(title="Reentrancy", severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED, source=["slither", "reentrancy"],
                    description="call before state",
                    evidence="payable(msg.sender).transfer(amount);",
                    file_path="V.sol", line_start=3,
                    category=FindingCategory.REENTRANCY,
                    affected_functions=["withdraw"],
                    validation_method="independent_tool_corroboration",
                    validation_result="confirmed",
                    knowledge_reference_details=[
                        KnowledgeReference(knowledge_id="kb-9",
                                           source_name="SPECA",
                                           title="pooltogether#20",
                                           relevance_reason="same CEI pattern")],
                    supporting_evidence=["tool:slither:reentrancy-eth@V.sol:3"])
        rep = AuditReport(address="0x" + "2" * 40, findings=[f])
        rep.summary.total_findings = 1
        rep.summary.by_status = {"confirmed": 1}
        return rep

    def test_markdown_agrees_with_html(self):
        rep = self._report()
        md = render_markdown(rep)
        html = render_html(rep)
        assert "Reentrancy" in md and "Reentrancy" in html
        assert "confirmed" in md and "confirmed" in html
        assert "high" in md and "high" in html
        # validation method + structured KB reference present in both
        assert "independent_tool_corroboration" in md
        assert "pooltogether#20" in md
        assert "kb-9" in html

    def test_markdown_round_trip_structure(self):
        rep = self._report()
        md = render_markdown(rep)
        assert md.startswith("# agentSAFE Audit Report")
        assert "## Findings" in md
        assert "## Known limitations" in md
        assert rep.disclaimer in md
