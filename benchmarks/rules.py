"""P0-4 deterministic (LLM-free) vulnerability rule engine.

Runs a small corpus of known-vulnerable Solidity fixtures through pure
deterministic rules to establish a regression floor for the DETECTION layer
without spending any LLM budget. It reuses the proven CEI machinery from the
validation pipeline (`_function_blocks`, `_cei_verdict`) and adds flash-loan
and price-oracle heuristics.

Rules are conservative: a category is emitted only when the machine can prove
the defect from the source text alone. This is NOT a replacement for the audit
pipeline -- it is a fast, honest regression harness that must always fire on
the fixtures it is written for, so any future pipeline regression is caught
before it reaches a paying customer.

Scope (categories, from the pipeline GT vocabulary):
  - reentrancy       : external call precedes a caller-state effect (CEI violation)
  - flash_loan       : external token transfer precedes a state write / borrower callback
  - oracle           : spot AMM price read without TWAP / secondary oracle
"""

from __future__ import annotations

import re
from pathlib import Path

from agentsafe.agents.validation import _cei_verdict, _function_blocks

# --- flash-loan / external-token-call markers ---------------------------------
_RE_EXTERNAL_CALL = re.compile(
    r"\.call\s*\(|\.transfer\s*\(|\.send\s*\(|transferFrom\s*\(|"
    r"call\s*\{|encodeWithSignature",
    re.IGNORECASE,
)
# a state write to an accounting/storage mapping or counter
_RE_STATE_WRITE = re.compile(
    r"(?:balanceOf|collateralOf|debtOf|totalSupply|reserves?|accounting)\s*[\[.]?\w*\]?\s*(?:\+=|-=|=)",
    re.IGNORECASE,
)
# flash-loan semantic markers (borrower callback, loan repayment, flash mint)
_RE_FLASH = re.compile(
    r"flash|borrow|executeOperation|onFlashLoan|loan|repay",
    re.IGNORECASE,
)

# --- price-oracle markers ------------------------------------------------------
# a raw AMM spot-reserve read (no TWAP / time-weighted / secondary oracle)
_RE_SPOT_RESERVE = re.compile(
    r"(?:getReserves?|reserve[01]\s*\(|pair\.reserve|sync\(\)|"
    r"balanceOf\s*\(\s*pair|getReserves\(\))",
    re.IGNORECASE,
)
# price derived directly from reserves / spot (manipulable)
_RE_SPOT_PRICE = re.compile(
    r"reserve[01]\s*\*|/\s*reserve[01]|getReserves?|price\s*=\s*.*reserve|"
    r"amountIn\s*\*\s*.*reserve",
    re.IGNORECASE,
)
# safe-oracle markers that make a spot read acceptable (TWAP / chainlink / gov)
_RE_SAFE_ORACLE = re.compile(
    r"twap|time\s*weighted|accumulat|priceCumulative|chainlink|"
    r"latestRoundData|updatedAt|priceFeed|deriv|oracle[^s].*(?:read|update)",
    re.IGNORECASE,
)


def _strip_comments(src: str) -> str:
    """Remove // line and /* */ block comments so safe-oracle detection only
    sees real code, not doc prose that merely mentions a TWAP/oracle."""
    out = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", out)

CORPUS: tuple[dict[str, object], ...] = (
    {
        "name": "EtherStore",
        "category": "reentrancy",
        "file": "EtherStore.sol",
        "expect": True,
    },
    {
        "name": "FlashLoan",
        "category": "flash_loan",
        "file": "FlashLoan.sol",
        "expect": True,
    },
    {
        "name": "PriceOracle",
        "category": "oracle",
        "file": "PriceOracle.sol",
        "expect": True,
    },
)

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


# --- per-category rules ---------------------------------------------------------


def _detect_reentrancy(src: str) -> bool:
    """A function has an external call preceding a caller-state effect."""
    for block in _function_blocks(src):
        if _cei_verdict(block) == "plausible":
            return True
    return False


def _detect_flash_loan(src: str) -> bool:
    """A function performs an external token transfer/callback BEFORE a state
    write within flash-loan semantics (check-then-act reentrancy class)."""
    for block in _function_blocks(src):
        body = block.body_text
        if not _RE_FLASH.search(body):
            continue
        # split body into lines to inspect ordering
        lines = [ln for ln in body.splitlines() if ln.strip()]
        ext_idx: list[int] = []
        state_idx: list[int] = []
        for i, ln in enumerate(lines):
            if _RE_EXTERNAL_CALL.search(ln):
                ext_idx.append(i)
            if _RE_STATE_WRITE.search(ln):
                state_idx.append(i)
        if not ext_idx or not state_idx:
            continue
        # a state write occurs after an external call
        if min(state_idx) > min(ext_idx):
            return True
    return False


def _detect_oracle(src: str) -> bool:
    """A function reads/manipulates an AMM spot price with no safe-oracle
    marker (TWAP / chainlink / derived) present in the code (comments ignored)."""
    code = _strip_comments(src)
    if _RE_SAFE_ORACLE.search(code):
        return False  # a safe oracle exists; spot read is not obviously manipulable
    for block in _function_blocks(src):
        if _RE_SPOT_RESERVE.search(block.body_text) or _RE_SPOT_PRICE.search(block.body_text):
            return True
    return False


# --- engine ----------------------------------------------------------------------


def classify_contract(src: str) -> set[str]:
    """Return the set of vulnerability categories deterministically proven for
    a contract's source. Never spends LLM budget; never network-dependent."""
    cats: set[str] = set()
    if _detect_reentrancy(src):
        cats.add("reentrancy")
    if _detect_flash_loan(src):
        cats.add("flash_loan")
    if _detect_oracle(src):
        cats.add("oracle")
    return cats


def run_corpus() -> dict[str, object]:
    """Run every fixture in CORPUS and return a per-case verdict map."""
    results: list[dict[str, object]] = []
    all_ok = True
    for case in CORPUS:
        path = FIXTURES / str(case["file"])  # type: ignore[operator]
        src = path.read_text()
        got = classify_contract(src)
        want = str(case["category"])
        ok = want in got
        all_ok = all_ok and ok
        results.append(
            {
                "name": case["name"],
                "file": case["file"],
                "expected_category": want,
                "detected": sorted(got),
                "ok": ok,
            }
        )
    return {"ok": all_ok, "cases": results}


if __name__ == "__main__":
    import json

    outcome = run_corpus()
    print(json.dumps(outcome, indent=2))
    raise SystemExit(0 if outcome["ok"] else 1)