"""Stage 11.9 — LLM duplicate merging + severity wiring (AgentLISA-style
validation-driven dedup: same bug reported by several agents must merge to
one finding; distinct bugs must never fuse)."""

from __future__ import annotations

from agentsafe.report import merge_findings, build_report
from agentsafe.schemas import (
    Finding, FindingStatus, Severity, LLMUsage,
)


def _llm(**kw) -> Finding:
    base = dict(
        title="Reentrancy vulnerability in withdraw()",
        severity="high",
        status=FindingStatus.POTENTIAL,
        source=["reentrancy"],
        description="state updated after external call",
        evidence="(bool sent,) = msg.sender.call{value: bal}(\"\");",
        file_path="EtherStore.sol",
        line_start=30,
        confidence=0.7,
    )
    base.update(kw)
    return Finding(**base)


def test_three_agents_same_bug_merge_to_one():
    dup = [
        _llm(source=["access_control"],
             title="Reentrancy vulnerability in EtherStore.withdraw()"),
        _llm(source=["accounting"],
             title="Reentrancy vulnerability in EtherStore.withdraw()"),
        _llm(source=["general_discovery"],
             title="Reentrancy vulnerability in EtherStore.withdraw()",
             evidence="(bool sent,) = msg.sender.call{value: bal}(\"\");"),
    ]
    out = merge_findings([], dup)
    assert len(out) == 1, f"expected 1 merged finding, got {len(out)}"
    assert set(out[0].source) == {
        "access_control", "accounting", "general_discovery"}


def test_distinct_bugs_nearby_lines_never_fuse():
    a = _llm(title="Allowance race condition on approve()", line_start=36,
             evidence="allowance[msg.sender][guy] = wad;")
    b = _llm(title="Unusual transfer() implementation", line_start=41,
             evidence="return transferFrom(msg.sender, dst, wad);")
    out = merge_findings([], [a, b])
    assert len(out) == 2, f"distinct bugs must not fuse, got {len(out)}"


def test_build_report_dedups_cross_agent():
    findings = [
        _llm(source=["reentrancy"]),
        _llm(source=["accounting"],
             title="Reentrancy vulnerability in EtherStore.withdraw()"),
    ]
    rep = build_report(
        address="0x" + "c0" * 20, task_id=None, is_verified_source=True,
        tool_findings=[], llm_findings=findings,
        tools_executed=["slither"], tools_failed=[], tool_versions={},
        llm_usage=LLMUsage(total_calls=1), limitations=[], errors=[],
        execution_time_seconds=1.0,
    )
    assert rep.summary.total_findings == 1
