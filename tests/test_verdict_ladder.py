"""Section 8 — explicit verdict ladder + adversarial reconciliation.

Pins:
- the six-verdict vocabulary exists (confirmed/high_confidence/potential/
  informational/rejected/unverified plus needs_manual_review for humans);
- severity maps the new states conservatively (never inflated);
- validation assigns high_confidence for KB-supported-but-unreproduced claims;
- reentrancy claims on an already-guarded function are contradicted by the
  existing protection;
- a challenge preserves BOTH the discovery claim and the challenge, and records
  that the disagreement was resolved by evidence (no majority vote);
- the report surfaces the new verdict labels.
"""

from __future__ import annotations

from agentsafe.agents.adversarial import AdversarialVerifier
from agentsafe.agents.validation import ValidationAgent
from agentsafe.report import build_report
from agentsafe.report_render import render_html, render_markdown
from agentsafe.schemas import (
    Finding,
    FindingCategory,
    FindingStatus,
    LLMUsage,
    Severity,
)
from agentsafe.severity import assess

GUARDED_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract R {",                                              # 2
        "    uint256 private locked;",                               # 3
        "    modifier nonReentrant() {",                             # 4
        '        require(locked == 0, "reentrant");',                # 5
        "        locked = 1; _; locked = 0;",                        # 6
        "    }",                                                     # 7
        "    uint256 public balances;",                              # 8
        "    function withdraw() external nonReentrant {",           # 9
        '        (bool ok, ) = msg.sender.call{value: 1}("");',      # 10
        '        require(ok, "x");',                                 # 11
        "        balances = 0;",                                     # 12
        "    }",                                                     # 13
        "}",                                                         # 14
    ]
)

PLAIN_SRC = "contract A { uint256 x; function f() external { x = 1; } }"


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(needle)


def test_verdict_states_exist():
    finals = FindingStatus.final_states()
    for s in (
        FindingStatus.CONFIRMED,
        FindingStatus.HIGH_CONFIDENCE,
        FindingStatus.POTENTIAL,
        FindingStatus.INFORMATIONAL,
        FindingStatus.REJECTED,
        FindingStatus.UNVERIFIED,
    ):
        assert s in finals


class TestSeverityMapping:
    def _f(self, status, sev="high"):
        return Finding(
            title="t", severity=sev, status=status, source=["s"],
            description="d", evidence="e = 1;",
        )

    def test_high_confidence_capped_at_medium(self):
        sev, basis = assess(self._f(FindingStatus.HIGH_CONFIDENCE))
        assert sev is Severity.MEDIUM and "unvalidated" in basis

    def test_unverified_is_informational(self):
        assert assess(self._f(FindingStatus.UNVERIFIED))[0] is Severity.INFO


class TestValidationHighConfidence:
    def _finding(self, src):
        return Finding(
            title="Missing authorization on f()",
            severity="high",
            status=FindingStatus.LLM_SUGGESTED,
            source=["access_control"],
            description="f() is callable without any authorization check",
            evidence="x = 1;",
            preconditions="any external account can call f()",
            attack_scenario="1) call f(); 2) x is written without authorization",
            impact="unauthorized state change",
            file_path="A.sol",
            line_start=_line_of(src, "x = 1;"),
            category=FindingCategory.ACCESS_CONTROL,
        )

    def test_kb_supported_claim_is_high_confidence(self):
        out = ValidationAgent().validate(
            [self._finding(PLAIN_SRC)], [], {"A.sol": PLAIN_SRC},
            kb_evidence=[{"category": "access_control"}],
        )
        f = out.findings[0]
        assert f.status is FindingStatus.HIGH_CONFIDENCE
        assert f.metadata["validation"]["rule"] == "hc0_kb_supported"

    def test_without_kb_support_is_only_potential(self):
        out = ValidationAgent().validate(
            [self._finding(PLAIN_SRC)], [], {"A.sol": PLAIN_SRC},
        )
        assert out.findings[0].status is FindingStatus.POTENTIAL


class TestExistingGuardProtection:
    def test_reentrancy_claim_on_guarded_function_is_downgraded(self):
        f = Finding(
            title="Reentrancy in withdraw() via external call before state update",
            severity="high",
            status=FindingStatus.POTENTIAL,
            source=["reentrancy"],
            description="the external call precedes the balance update",
            evidence='(bool ok, ) = msg.sender.call{value: 1}("");',
            file_path="R.sol",
            line_start=_line_of(GUARDED_SRC, "msg.sender.call"),
            category=FindingCategory.REENTRANCY,
        )
        res = AdversarialVerifier().review([], [f], {"R.sol": GUARDED_SRC}, False)
        out = res.llm_findings[0]
        assert out.status is FindingStatus.INFORMATIONAL
        assert out.metadata["challenge"]["rule"] == "pr0_existing_guard"
        # Step 3: both arguments preserved + resolved by evidence
        rec = out.metadata["reconciliation"]
        assert rec["discovery"]["title"] == f.title
        assert rec["challenge"]["rule"] == "pr0_existing_guard"
        assert "no majority vote" in rec["resolved_by"]


class TestReportVerdictLabels:
    def _report(self, *findings):
        return build_report(
            address="0x" + "ab" * 20,
            task_id="t",
            is_verified_source=True,
            tool_findings=[],
            llm_findings=list(findings),
            tools_executed=["slither"],
            tools_failed=[],
            tool_versions={},
            llm_usage=LLMUsage(),
            limitations=[],
            errors=[],
            execution_time_seconds=1.0,
        )

    def test_high_confidence_and_unverified_labels_render(self):
        hc = Finding(
            title="KB-supported issue", severity="high",
            status=FindingStatus.HIGH_CONFIDENCE, source=["accounting"],
            description="strongly supported", evidence="e = 1;",
        )
        unv = Finding(
            title="Insufficient evidence", severity="medium",
            status=FindingStatus.UNVERIFIED, source=["oracle"],
            description="cannot conclude", evidence="e = 2;",
        )
        rep = self._report(hc, unv)
        html = render_html(rep)
        md = render_markdown(rep)
        assert "High confidence" in html and "Unverified" in html
        assert "high_confidence" in md and "unverified" in md
        # never counted as confirmed
        assert rep.summary.by_status.get("confirmed", 0) == 0
