"""P0-4: deterministic (LLM-free) regression corpus for the detection layer.

Verifies that known-vulnerable fixtures are ALWAYS detected by the pure
deterministic rule engine (no LLM budget), and that known-safe fixtures are
NOT false-positived. This is the regression floor that must stay green before
a paying customer ever receives a report.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "benchmarks"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from rules import classify_contract, run_corpus  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def _src(name: str) -> str:
    return (FIXTURES / name).read_text()


# --- positive: known-vulnerable fixtures must always fire -----------------------


@pytest.mark.parametrize(
    "fixture,expected",
    [
        ("EtherStore.sol", "reentrancy"),
        ("FlashLoan.sol", "flash_loan"),
        ("PriceOracle.sol", "oracle"),
    ],
)
def test_vulnerable_fixture_detected(fixture: str, expected: str) -> None:
    got = classify_contract(_src(fixture))
    assert expected in got, (
        f"{fixture} must be detected as '{expected}', got {sorted(got)}"
    )


def test_corpus_all_green() -> None:
    """The full corpus regression must pass (this is the commercial floor)."""
    outcome = run_corpus()
    assert outcome["ok"] is True, outcome


# --- negative: known-safe fixtures must NOT false-positive -----------------------


def test_safe_reentrancy_not_flagged() -> None:
    # CEI-satisfied withdraw: state update precedes external call.
    assert "reentrancy" not in classify_contract(_src("Safe.sol"))


def test_safe_oracle_not_flagged() -> None:
    # TWAP-derived price is a safe oracle, not a manipulable spot read.
    assert "oracle" not in classify_contract(_src("Safe.sol"))


def test_safe_flash_not_flagged() -> None:
    # Internal accounting settled before the external borrower callback.
    assert "flash_loan" not in classify_contract(_src("Safe.sol"))


# --- determinism / no-side-effect guarantees -------------------------------------


def test_classify_is_pure() -> None:
    """Running classify twice on the same source yields identical results
    (no mutable state, no network, no LLM budget)."""
    src = _src("EtherStore.sol")
    first = classify_contract(src)
    second = classify_contract(src)
    assert first == second
    assert first == {"reentrancy"}


def test_unknown_source_returns_empty() -> None:
    assert classify_contract("pragma solidity ^0.8.0; contract X {}") == set()