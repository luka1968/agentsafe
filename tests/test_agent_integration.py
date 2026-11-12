"""Agent-integration tests (Task: Agent Integration).

Covers:
  * KB snippets carry the evidence duties (preconditions match/mismatch,
    code-path analysis, impact reachability, secure counterexample,
    source-level evidence, confidence) and the supporting-evidence-only rule
  * a KB record alone NEVER confirms a finding: the validator requires
    source-level evidence regardless of KB corroboration
"""

import pytest

from agentsafe.intel.render import render_kb_snippets
from agentsafe.schemas import Finding, FindingStatus, Severity

KB_REC = {
    "id": "KB-2025-104", "category": "reentrancy", "protocol_type": "AMM",
    "mechanism": "read-only reentrancy via callback window",
    "root_cause": "state finalized after external call",
    "preconditions": ["external call before state finalize",
                      "consumer reads mid-callback"],
    "impact": "cross-contract loss",
    "remediation": "CEI + view guards",
    "source": "s", "url": "https://x.test/1",
}


class TestSnippetEvidenceDuties:
    def test_all_evidence_duties_present(self):
        out = render_kb_snippets([KB_REC])
        for duty in ("SUPPORTING EVIDENCE", "preconditions", "code path",
                     "impact", "counterexample", "source-level evidence",
                     "confidence"):
            assert duty in out, f"missing evidence duty: {duty}"

    def test_no_auto_proof_rule(self):
        out = render_kb_snippets([KB_REC])
        assert "never automatic proof" in out
        assert "solely" in out  # do not report solely because a record exists


class TestKbAloneNeverConfirms:
    """A KB record is supporting evidence only: without source-level code
    evidence the validator must NOT confirm, even with KB corroboration."""

    def _finding(self, *, with_evidence: bool) -> Finding:
        return Finding(
            title="Reentrancy in withdraw", severity=Severity.HIGH,
            status=FindingStatus.LLM_SUGGESTED, source=["reentrancy"],
            description="external call before state update",
            evidence=('(bool ok,) = msg.sender.call{value: a}("");\n'
                      'balances[msg.sender] -= a;')
            if with_evidence else "",
            file_path="T.sol", line_start=10, confidence=0.8)

    def _validate(self, f):
        from agentsafe.agents.validation import ValidationAgent
        v = ValidationAgent()
        # kb_evidence contains a corroborating reentrancy record
        kb_evidence = [dict(KB_REC)]
        return v.validate([f], [], {"T.sol": (
            "pragma solidity ^0.8;\ncontract T {\n"
            "  mapping(address=>uint) balances;\n"
            "  function withdraw(uint a) external {\n"
            '    (bool ok,) = msg.sender.call{value: a}("");\n'
            "    balances[msg.sender] -= a;\n"
            "    require(ok);\n"
            "  }\n}\n")}, kb_evidence=kb_evidence).findings[0]

    def test_kb_with_evidence_can_confirm(self):
        r = self._validate(self._finding(with_evidence=True))
        # CEI violation + KB corroboration -> confirmed is allowed
        assert r.status in (FindingStatus.CONFIRMED, FindingStatus.POTENTIAL)

    def test_kb_alone_never_confirms(self):
        r = self._validate(self._finding(with_evidence=False))
        # KB corroborates, but there is NO source evidence: must not confirm
        assert r.status != FindingStatus.CONFIRMED, (
            "KB record alone must never confirm a finding")

    def test_snippet_includes_secure_counterexample_field(self):
        rec = dict(KB_REC, security_pattern="checks-effects-interactions",
                   fp_patterns="a trailing call is not a finding",
                   evidence_required="show a post-call state write")
        out = render_kb_snippets([rec])
        assert "security pattern" in out and "false-positive shapes" in out