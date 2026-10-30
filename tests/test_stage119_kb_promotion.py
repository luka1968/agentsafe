"""Stage 11.9 - KB-corroborated deterministic reentrancy promotion (AgentLISA
validation-driven: a machine-proven CEI violation + a matching knowledge-base
reentrancy case = double evidence, so the claim promotes beyond potential)."""

from __future__ import annotations

import pathlib

from agentsafe.agents.validation import ValidationAgent
from agentsafe.schemas import Finding, FindingStatus

SRC = pathlib.Path("tests/fixtures/EtherStore.sol").read_text()
SEGMENTS = {"EtherStore.sol": SRC}


def _reentrancy() -> Finding:
    return Finding(
        title="Reentrancy vulnerability in withdraw()",
        severity="high",
        status=FindingStatus.LLM_SUGGESTED,
        source=["reentrancy"],
        description="external call before state update allows re-entry",
        evidence='(bool sent, ) = msg.sender.call{value: bal}("");',
        file_path="EtherStore.sol",
        line_start=14,
        confidence=0.75,
    )


def test_kb_reentrancy_case_promotes_cei_violation_to_confirmed():
    v = ValidationAgent()
    out = v.validate(
        [_reentrancy()], [], SEGMENTS,
        kb_evidence=[{"id": "KB-2025-001", "category": "reentrancy",
                      "mechanism": "external call before state update"}],
    )
    f = out.findings[0]
    assert f.status is FindingStatus.CONFIRMED
    assert f.metadata["validation"]["rule"] == "re1_cei_violation_kb"
    assert f.metadata["validation"].get("kb_corroborated") is True
    assert f.severity is f.proposed_severity  # rubric: confirmed, no reductions


def test_no_kb_case_keeps_cei_violation_as_potential():
    v = ValidationAgent()
    out = v.validate([_reentrancy()], [], SEGMENTS)
    f = out.findings[0]
    assert f.status is FindingStatus.POTENTIAL
    assert f.metadata["validation"].get("kb_corroborated") is not True


def test_kb_case_of_wrong_category_does_not_promote():
    v = ValidationAgent()
    out = v.validate(
        [_reentrancy()], [], SEGMENTS,
        kb_evidence=[{"id": "KB-x", "category": "weak-prng"}],
    )
    f = out.findings[0]
    assert f.status is FindingStatus.POTENTIAL
