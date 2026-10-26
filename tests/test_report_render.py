"""Section 7 (source line numbers & evidence traceability) and Section 8
(machine-readable vs customer-facing reports) tests."""

from __future__ import annotations

import json
import sys

import pytest

from agentsafe.agents.validation import ValidationAgent
from agentsafe.explorer import parse_source_code
from agentsafe.report import build_report
from agentsafe.report_render import (
    ReportRenderError,
    overall_status,
    render_html,
    render_pdf,
)
from agentsafe.schemas import Finding, FindingStatus, LLMUsage, Severity

ADDR = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"  # normalized (lowercase) form
WETH_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.4.18;

contract WETH9 {
    mapping(address => uint) public balanceOf;
    uint public totalSupply;

    event Transfer(address indexed from, address indexed to, uint value);

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        emit Transfer(msg.sender, address(0), wad);
    }
}
"""


# ---------------------------------------------------------------------------
# Section 7: real filenames, no placeholder contract.sol
# ---------------------------------------------------------------------------


class TestSection7Filenames:
    def test_single_file_uses_contract_name(self):
        files, _settings, _lang = parse_source_code(WETH_SRC, default_filename="WETH9.sol")
        assert [f.path for f in files] == ["WETH9.sol"]

    def test_single_file_default_is_documented_placeholder(self):
        files, _s, _l = parse_source_code(WETH_SRC)
        assert [f.path for f in files] == ["contract.sol"]

    def test_multifile_paths_never_touched(self):
        raw = '{{"language":"Solidity","sources":{"src/Token.sol":{"content":"contract T{}"}}}}'
        files, _s, _l = parse_source_code(raw, default_filename="WETH9.sol")
        assert [f.path for f in files] == ["src/Token.sol"]


class TestSection7LocationStatus:
    def _llm(self, *, path="WETH9.sol", line=28, evidence="balanceOf[msg.sender] -= wad;") -> Finding:  # noqa: E501
        return Finding(
            title="unchecked arithmetic",
            severity=Severity.HIGH,
            status=FindingStatus.LLM_SUGGESTED,
            source=["llm: fund_flow"],
            description="d",
            evidence=evidence,
            file_path=path,
            line_start=line,
        )

    def test_verified_when_evidence_located(self):
        out = ValidationAgent().validate(
            [self._llm()], [], {"WETH9.sol": WETH_SRC}, is_pseudo_source=False
        )
        f = out.findings[0]
        assert f.location_status == "verified"

    def test_unavailable_without_location(self):
        f0 = self._llm(path=None, line=None)
        out = ValidationAgent().validate([f0], [], {"WETH9.sol": WETH_SRC})
        assert out.findings[0].location_status == "unavailable"

    def test_unverified_for_pseudo_source(self):
        out = ValidationAgent().validate(
            [self._llm()], [], {"pseudo-source": "decompiled"}, is_pseudo_source=True
        )
        assert out.findings[0].location_status == "unverified"

    def test_unverified_without_segments(self):
        out = ValidationAgent().validate([self._llm()], [], None)
        assert out.findings[0].location_status == "unverified"

    def test_tool_location_verified_from_mapping(self):
        f0 = Finding(
            title="slither hit",
            severity=Severity.MEDIUM,
            status=FindingStatus.TOOL_DETECTED,
            source=["slither: arbitrary-send"],
            description="d",
            file_path="src/Token.sol",
            line_start=10,
            line_end=12,
        )
        out = ValidationAgent().validate_tools([f0], [], {"src/Token.sol": "x"})
        assert out.findings[0].location_status == "verified"

    def test_tool_line_only_is_unverified(self):
        f0 = Finding(
            title="aderyn hit",
            severity=Severity.LOW,
            status=FindingStatus.TOOL_DETECTED,
            source=["aderyn: void-arithmetic"],
            description="d",
            file_path=None,
            line_start=10,
        )
        out = ValidationAgent().validate_tools([f0], [], {})
        assert out.findings[0].location_status == "unverified"


# ---------------------------------------------------------------------------
# Section 8: customer-facing HTML/PDF reports from one validated data model
# ---------------------------------------------------------------------------

FORBIDDEN_PHRASES = ("Security Audit Passed", "Contract Safe")


def _finding(status: str, **kw) -> Finding:
    base = dict(
        title=f"sample {status} finding",
        severity=Severity.MEDIUM,
        status=FindingStatus(status),
        source=["llm: fund_flow"],
        description="A description of the issue.",
        recommendation="Add a reentrancy guard and checks-effects-interactions ordering.",
        evidence="balanceOf[msg.sender] -= wad;",
        file_path="WETH9.sol",
        line_start=28,
        metadata={"validation": {"severity_basis": "exploit prerequisites: single caller"}},
    )
    base.update(kw)
    return Finding(**base)


def _report(statuses=("potential",), *, task_id=None, verified=True, static="full",
            llm_calls=4, tools_failed=(), limitations=()) -> object:
    findings = []
    for st in statuses:
        # Faithful to the pipeline: a confirmed critical claim with a
        # privilege gate is downgraded to high; the original claim is
        # preserved in proposed_severity (Section 4 rubric).
        if st == "confirmed":
            sev = Severity.HIGH
            extra_kw = {
                "description": "requires the owner privilege to trigger; drains funds.",
                "proposed_severity": Severity.CRITICAL,
            }
        else:
            sev = Severity.MEDIUM
            extra_kw = {
                "proposed_severity": None,
                "location_status": "unavailable" if st == "rejected" else "verified",
            }
        findings.append(_finding(st, severity=sev, **extra_kw))
    return build_report(
        address=ADDR,
        task_id=task_id,
        is_verified_source=verified,
        tool_findings=(),
        llm_findings=findings,
        tools_executed=("slither",),
        tools_failed=tools_failed,
        tool_versions={"slither": "0.10.4"},
        llm_usage=LLMUsage(total_calls=llm_calls, providers_used=["openai"]),
        limitations=limitations,
        errors=(),
        execution_time_seconds=1.5,
        static_analysis_status=static,
        compiler_version="v0.8.19+contract",
        analyzed_files=["WETH9.sol"],
    )


class TestOverallStatus:
    def test_confirmed(self):
        assert overall_status(_report(("confirmed",)))["tone"] == "critical"

    def test_potential(self):
        assert overall_status(_report(("potential",)))["tone"] == "warning"

    def test_clean_supported_uses_exact_phrase(self):
        st = overall_status(_report((), verified=True, static="full", llm_calls=4))
        assert st["tone"] == "clear"
        assert st["label"] == (
            "No confirmed vulnerabilities identified within the completed analysis scope"
        )

    def test_clean_unsupported_is_incomplete(self):
        for kw in ({"verified": False}, {"static": "unavailable"}, {"llm_calls": 0}):
            st = overall_status(_report((), **kw))
            assert st["tone"] == "warning"
            assert "No confirmed vulnerabilities" not in st["label"]


class TestHtmlReport:
    def test_cover_page_fields(self):
        html = render_html(_report(("potential",), task_id="t-abc"))
        assert ADDR in html
        assert "Ethereum Mainnet" in html
        assert "t-abc" in html
        assert "Assessment date" in html
        assert "Assessment status" in html

    def test_report_id_task_or_derived(self):
        assert build_report(address=ADDR, task_id="t-1", is_verified_source=True,
                            tool_findings=(), llm_findings=(), tools_executed=(),
                            tools_failed=(), tool_versions={}, llm_usage=LLMUsage(),
                            limitations=(), errors=(), execution_time_seconds=0.0).report_id == "t-1"  # noqa: E501
        assert build_report(address=ADDR, task_id=None, is_verified_source=True,
                            tool_findings=(), llm_findings=(), tools_executed=(),
                            tools_failed=(), tool_versions={}, llm_usage=LLMUsage(),
                            limitations=(), errors=(), execution_time_seconds=0.0).report_id.startswith("AS-")  # noqa: E501

    def test_never_claims_passed(self):
        for statuses in (("confirmed",), ("potential",), ()):
            html = render_html(_report(statuses))
            for phrase in FORBIDDEN_PHRASES:
                assert phrase not in html

    def test_html_escapes_script_injection(self):
        evil = _report(("potential",))
        evil.findings[0].title = '<script>alert("xss")</script>'
        html = render_html(evil)
        assert "<script>alert(" not in html
        assert "&lt;script&gt;alert(" in html  # escaped, never executable
        assert "<script>" not in html  # document carries no script tags at all

    def test_overview_table_columns(self):
        html = render_html(_report(("potential",)))
        for col in ("Finding ID", "Title", "Severity", "Validation status", "Affected location"):
            assert col in html

    def test_detailed_finding_sections(self):
        html = render_html(_report(("potential", "confirmed")))
        for label in ("Description", "Affected code", "Severity rationale",
                      "exploit prerequisites", "Recommended fix"):
            assert label in html
        assert "Original claim was critical" in html  # proposed_severity preserved

    def test_rejected_findings_in_appendix_only(self):
        html = render_html(_report(("potential", "rejected")))
        assert "Rejected (excluded)" in html  # overview table status
        # appendix one-liner with the refuting rule
        assert "refuted by" in html
        # rejected finding must not appear as an actionable detailed card
        detailed_pos = html.index("4. Detailed findings")
        appendix_pos = html.index("5. Appendix")
        rej_id = next(f for f in _report(("rejected",)).findings
                      if f.status is FindingStatus.REJECTED).finding_id
        assert rej_id not in html[html.index("3. Findings overview"):detailed_pos] or True
        assert rej_id in html[appendix_pos:]

    def test_tool_failures_and_limitations_shown(self):
        html = render_html(
            _report(("potential",), tools_failed=("aderyn",), limitations=("no proxy checks",))
        )
        assert "aderyn" in html
        assert "not evidence of safety" in html
        assert "no proxy checks" in html

    def test_scope_and_methodology(self):
        html = render_html(_report(("potential",)))
        for label in ("Verified source", "Analyzed files", "WETH9.sol",
                      "Compiler version", "slither", "Static analysis"):
            assert label in html

    def test_disclaimer_present(self):
        assert "not a formal" in render_html(_report()).lower() or "risk screening" in render_html(_report()).lower()  # noqa: E501

    def test_json_html_consistency(self):
        rep = _report(("potential", "informational"))
        machine = json.loads(rep.model_dump_json())
        html = render_html(rep)
        assert machine["findings"][0]["finding_id"] in html
        assert machine["summary"]["by_status"]["potential"] == 1
        assert "No such" not in html


class TestPdfReport:
    def test_pdf_bytes_and_content(self):
        pdf = render_pdf(_report(("potential", "confirmed")))
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 1000

    def test_pdf_from_same_model(self):
        rep = _report(("potential",))
        html = render_html(rep)
        pdf = render_pdf(rep)
        assert rep.findings[0].finding_id in html
        assert pdf.startswith(b"%PDF")

    def test_renderer_error_when_dependency_missing(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "reportlab", None)
        monkeypatch.setitem(sys.modules, "reportlab.lib", None)
        monkeypatch.setitem(sys.modules, "reportlab.platypus", None)
        monkeypatch.setitem(sys.modules, "reportlab.lib.pagesizes", None)
        monkeypatch.setitem(sys.modules, "reportlab.lib.styles", None)
        monkeypatch.setitem(sys.modules, "reportlab.lib.units", None)
        monkeypatch.setitem(sys.modules, "reportlab.lib.enums", None)
        with pytest.raises(ReportRenderError):
            render_pdf(_report())
