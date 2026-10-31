"""Stage 11.10 - category attribution (P0): agents must tag findings; when
they do not, the validation engine infers a deterministic category so
category-based recall/tp metrics are real, not skewed to 'unknown'."""

from __future__ import annotations

import pathlib

from agentsafe.agents.base import _infer_category
from agentsafe.agents.validation import ValidationAgent
from agentsafe.schemas import Finding, FindingCategory, FindingStatus

SRC = pathlib.Path("tests/fixtures/EtherStore.sol").read_text()
SEGMENTS = {"EtherStore.sol": SRC}


def _finding(**kw) -> Finding:
    base = dict(
        title="Reentrancy vulnerability in withdraw()",
        severity="high",
        status=FindingStatus.LLM_SUGGESTED,
        source=["reentrancy"],
        description="external call before state update allows re-entry",
        evidence='(bool sent, ) = msg.sender.call{value: bal}("");',
        file_path="EtherStore.sol",
        line_start=14,
    )
    base.update(kw)
    return Finding(**base)


# --- _infer_category: deterministic inference --------------------------------
def test_infer_reentrancy_from_title():
    assert _infer_category(None, "Reentrancy vulnerability", "x", "x") \
        is FindingCategory.REENTRANCY


def test_infer_arithmetic_from_swc():
    assert _infer_category("SWC-101", "overflow", "x", "x") \
        is FindingCategory.ARITHMETIC


def test_infer_proxy_from_swc():
    assert _infer_category("SWC-112", "delegatecall", "x", "x") \
        is FindingCategory.PROXY


def test_infer_none_when_no_signal():
    assert _infer_category(None, "obscure comment", "nothing", "no") is None


# --- validation fallback: agent omits category, engine fills it --------------
def test_validation_fills_category_when_agent_omits():
    v = ValidationAgent()
    out = v.validate(
        [_finding(category=FindingCategory.UNKNOWN)], [], SEGMENTS
    )
    f = out.findings[0]
    assert f.category is FindingCategory.REENTRANCY


def test_validation_honors_explicit_category():
    v = ValidationAgent()
    out = v.validate(
        [_finding(category=FindingCategory.ACCOUNTING)], [], SEGMENTS
    )
    f = out.findings[0]
    assert f.category is FindingCategory.ACCOUNTING