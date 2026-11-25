# ruff: noqa: E501 - this module is a data-heavy benchmark fixture catalogue.
"""Section 14 — categorized benchmark & regression suite.

A repeatable, offline suite that drives the DETERMINISTIC decision layers
(validation → independent adversarial review → deployment context) over
representative vulnerable and secure/trap contracts, then computes per-category
and aggregate sklearn-style metrics.

Scope honesty: this measures the *verification* layers, which is where
false positives and missed findings are actually decided. Discovery is
LLM-driven and is exercised separately (benchmarks/eval_suite.py, live mode);
here each case supplies the candidate a specialist would emit, plus the real
source, so precision/recall of the decision plane can be measured reproducibly
without network or paid calls.

A secure/trap contract must NOT receive a fabricated vulnerability; a vulnerable
contract must NOT be cleared merely because no static tool flagged it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsafe.agents.adversarial import AdversarialVerifier
from agentsafe.agents.deployment import (
    DISPOSITION_EXISTING_EXPOSURE,
    build_deployment_context,
    finding_disposition,
)
from agentsafe.agents.validation import ValidationAgent
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.schemas import Finding, FindingCategory, FindingStatus
from agentsafe.severity import assess

__all__ = ["Case", "CASES", "decide", "evaluate", "metrics"]

ACTIONABLE = frozenset({
    FindingStatus.CONFIRMED,
    FindingStatus.HIGH_CONFIDENCE,
    FindingStatus.POTENTIAL,
})


# ---------------------------------------------------------------------------
# decision plane (mirrors the orchestrator's deterministic layers)
# ---------------------------------------------------------------------------

def decide(
    candidates: list[Finding],
    segments: dict[str, str],
    *,
    tool_findings: list[Finding] | None = None,
    verified: bool = True,
    compiler: str = "v0.8.19",
) -> list[Finding]:
    intel = extract_contract_intel(segments)
    v = ValidationAgent()
    out = v.validate(list(candidates), list(tool_findings or []), segments)
    findings = list(out.findings)
    cres = AdversarialVerifier().review(
        [], findings, segments, False, intel=intel
    )
    findings = list(cres.llm_findings)
    dctx = build_deployment_context(
        address="0x" + "00" * 20, is_verified_source=verified,
        compiler_version=compiler, intel=intel,
    )
    final: list[Finding] = []
    for f in findings:
        disp = finding_disposition(f, dctx)
        if disp != DISPOSITION_EXISTING_EXPOSURE and f.status in ACTIONABLE:
            nf = f.model_copy(deep=True)
            nf.proposed_severity = f.severity
            nf.status = FindingStatus.INFORMATIONAL
            nf.severity = assess(nf)[0]
            final.append(nf)
        else:
            final.append(f)
    return final


# ---------------------------------------------------------------------------
# case model
# ---------------------------------------------------------------------------

@dataclass
class Case:
    id: str
    category: str
    kind: str  # "vulnerable" | "secure"
    source: dict[str, str]
    candidates: list[Finding] = field(default_factory=list)
    tool_findings: list[Finding] = field(default_factory=list)
    compiler: str = "v0.8.19"
    expect_actionable: bool = True
    expect_rule: str | None = None


def _F(**kw) -> Finding:
    base = dict(
        title="issue", severity="high", status=FindingStatus.LLM_SUGGESTED,
        source=["benchmark"], description="root cause",
        evidence="x = 1;", file_path="C.sol", line_start=1,
        preconditions="attacker is an external account",
        attack_scenario="1) call the function", impact="state corruption",
    )
    base.update(kw)
    return Finding(**base)


# -- sources -----------------------------------------------------------------

WETH_FIXTURE = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "WETH.sol"
).read_text(encoding="utf-8")

REENTRANCY_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract ES {",
    "    mapping(address => uint256) private balances;",
    "    function withdraw() external {",
    "        uint256 b = balances[msg.sender];",
    '        (bool ok, ) = msg.sender.call{value: b}("");',
    '        require(ok, "x");',
    "        balances[msg.sender] = 0;",
    "    }",
    "}",
])
WETH_SRC = WETH_FIXTURE
CROSSFUNC_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract CF {",
    "    mapping(address => uint256) private balances;",
    "    function a() external {",
    "        uint256 b = balances[msg.sender];",
    '        (bool ok, ) = msg.sender.call{value: b}("");',
    '        require(ok, "x");',
    "    }",
    "    function b() external { balances[msg.sender] = 0; }",
    "}",
])
ACCESS_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract AC {",
    "    address private owner;",
    "    uint256 private x;",
    "    function setX(uint256 v) external { x = v; }",
    "}",
])
GATED_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract AC2 {",
    "    address private owner;",
    "    uint256 private x;",
    "    function setX(uint256 v) external onlyOwner { x = v; }",
    "}",
])
INIT_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract I {",
    "    address public owner;",
    "    function initialize(address o) external { owner = o; }",
    "}",
])
ACCT_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract A {",
    "    mapping(address => uint256) private bal;",
    "    uint256 private total;",
    "    function deposit() external payable {",
    "        bal[msg.sender] += msg.value; total += msg.value;",
    "    }",
    "    function withdraw(uint256 a) external {",
    "        bal[msg.sender] -= a;",
    '        (bool ok, ) = msg.sender.call{value: a}("");',
    '        require(ok, "x");',
    "    }",
    "}",
])
ORACLE_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract O {",
    "    address private pair;",
    "    function price() external view returns (uint256) {",
    "        (uint256 r, ) = pair.call(\"\");",
    "        return r;",
    "    }",
    "    function value(uint256 amt) external view returns (uint256) {",
    "        return amt * price();",
    "    }",
    "}",
])
SIG_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract S {",
    "    address private owner;",
    "    function exec(address to, uint256 amt, uint8 v, bytes32 r, bytes32 s) external {",
    "        address signer = ecrecover(keccak256(abi.encode(to, amt)), v, r, s);",
    "        require(signer == owner, \"bad sig\");",
    "        (bool ok, ) = to.call{value: amt}(\"\");",
    "        require(ok, \"x\");",
    "    }",
    "}",
])
TOKEN_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract T {",
    "    function pay(address tok, address to, uint256 a) external {",
    "        IERC20(tok).transfer(to, a);",
    "    }",
    "}",
    "interface IERC20 {",
    "    function transfer(address to, uint256 a) external returns (bool);",
    "}",
])
DOS_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract D {",
    "    address[] private users;",
    "    function airdrop() external {",
    "        for (uint256 i = 0; i < users.length; i++) {",
    "            payable(users[i]).transfer(1);",
    "        }",
    "    }",
    "}",
])
XCONTR_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract X {",
    "    address private ext;",
    "    mapping(address => uint256) private bal;",
    "    function f() external {",
    "        bal[msg.sender] = 0;",
    '        (bool ok, ) = ext.call("");',
    '        require(ok, "x");',
    "    }",
    "}",
])
LOGIC_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract B {",
    "    mapping(address => uint256) private shares;",
    "    function withdraw(uint256 s) external {",
    "        shares[msg.sender] -= s;",
    "        payable(msg.sender).transfer(s);",
    "    }",
    "}",
])
VIEW_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract V {",
    "    uint256 private fee;",
    "    function getFee() external view returns (uint256) { return fee; }",
    "}",
])
INTERNAL_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract P {",
    "    uint256 private x;",
    "    function poke() external { x = 1; }",
    "    function _orphan(uint256 v) internal { x = v; }",
    "}",
])
OVERFLOW_TOOL_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract Ov {",
    "    mapping(address => uint256) private balanceOf;",
    "    function batch(address[] memory rs, uint256 amount) external {",
    "        for (uint256 i = 0; i < rs.length; i++) {",
    "            balanceOf[rs[i]] += amount;",
    "        }",
    "    }",
    "}",
])
VENDOR_SRC = "\n".join([
    "pragma solidity ^0.8.0;",
    "contract E {",
    "    mapping(address => mapping(address => uint256)) private allowance;",
    "    function approve(address sp, uint256 v) external returns (bool) {",
    "        allowance[msg.sender][sp] = v;",
    "        return true;",
    "    }",
    "}",
])


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(needle)


def _reentrancy_case(cid, kind, src, *, expect_actionable, expect_rule=None):
    line = _line_of(src, ".transfer(") if ".transfer(" in src else _line_of(src, ".call{")
    return Case(
        id=cid, category="reentrancy", kind=kind,
        source={"C.sol": src},
        candidates=[_F(
            title="Reentrancy in withdraw()",
            category=FindingCategory.REENTRANCY,
            evidence=(src.splitlines()[line - 1].strip()),
            line_start=line,
            description="the external call precedes the balance update",
            file_path="C.sol",
        )],
        expect_actionable=expect_actionable, expect_rule=expect_rule,
    )


CASES: list[Case] = [
    # 1. Reentrancy
    _reentrancy_case("reentrancy_vuln", "vulnerable", REENTRANCY_SRC, expect_actionable=True),
    _reentrancy_case("reentrancy_cei_trap", "secure", WETH_SRC, expect_actionable=False,
                     expect_rule="re0_cei_satisfied"),
    # 2. Cross-function reentrancy
    Case("cross_function_vuln", "cross_function", "vulnerable", {"C.sol": CROSSFUNC_SRC},
         candidates=[_F(title="Cross-function reentrancy via a()/b()", category=FindingCategory.REENTRANCY,
                        evidence='(bool ok, ) = msg.sender.call{value: b}("");',
                        line_start=_line_of(CROSSFUNC_SRC, ".call{"), file_path="C.sol")]),
    # 3. Access control
    Case("access_control_vuln", "access_control", "vulnerable", {"C.sol": ACCESS_SRC},
         candidates=[_F(title="Missing access control on setX()", category=FindingCategory.ACCESS_CONTROL,
                        evidence="function setX(uint256 v) external { x = v; }",
                        line_start=_line_of(ACCESS_SRC, "x = v;"), file_path="C.sol")]),
    Case("authz_gated_trap", "access_control", "secure", {"C.sol": GATED_SRC},
         candidates=[_F(title="Missing access control on setX()", category=FindingCategory.ACCESS_CONTROL,
                        evidence="x = v;", line_start=_line_of(GATED_SRC, "x = v;"), file_path="C.sol")],
         expect_actionable=False, expect_rule="ac0_authz_gated_path"),
    # 4. Initialization
    Case("init_vuln", "initialization", "vulnerable", {"C.sol": INIT_SRC},
         candidates=[_F(title="Unprotected initialize() takeover", category=FindingCategory.ACCESS_CONTROL,
                        evidence="owner = o;", line_start=_line_of(INIT_SRC, "owner = o;"), file_path="C.sol")]),
    # 5. Accounting
    Case("accounting_vuln", "accounting", "vulnerable", {"C.sol": ACCT_SRC},
         candidates=[_F(title="total not decremented on withdraw (accounting drift)",
                        category=FindingCategory.ACCOUNTING,
                        evidence="bal[msg.sender] -= a;",
                        line_start=_line_of(ACCT_SRC, "bal[msg.sender] -= a;"), file_path="C.sol")]),
    # 6. Arithmetic
    Case("arithmetic_vuln", "arithmetic", "vulnerable", {"C.sol": OVERFLOW_TOOL_SRC},
         candidates=[_F(title="Integer overflow in batch()", category=FindingCategory.ARITHMETIC,
                        severity="critical",
                        description="amount is attacker-controlled and unchecked; overflow lets an attacker inflate balances",
                        evidence="balanceOf[rs[i]] += amount;",
                        line_start=_line_of(OVERFLOW_TOOL_SRC, "balanceOf[rs[i]] += amount;"),
                        file_path="C.sol")],
         tool_findings=[_F(title="[slither] integer-overflow", severity="critical",
                           status=FindingStatus.TOOL_DETECTED, source=["slither"],
                           detector_id="integer-overflow",
                           evidence="balanceOf[rs[i]] += amount;",
                           line_start=_line_of(OVERFLOW_TOOL_SRC, "balanceOf[rs[i]] += amount;"),
                           file_path="C.sol")],
         expect_rule="cr0"),
    Case("arith_theoretical_trap", "arithmetic", "secure", {"C.sol": WETH_SRC},
         candidates=[_F(title="Integer Overflow in deposit()", category=FindingCategory.ARITHMETIC,
                        severity="critical",
                        description="arithmetic lacks SafeMath; could theoretically overflow",
                        evidence="balanceOf[msg.sender] += msg.value;",
                        line_start=_line_of(WETH_SRC, "balanceOf[msg.sender] += msg.value;"),
                        file_path="C.sol")],
         compiler="v0.4.18", expect_actionable=False,
         expect_rule="ov0_theoretical_only"),
    # 7. Oracle
    Case("oracle_vuln", "oracle", "vulnerable", {"C.sol": ORACLE_SRC},
         candidates=[_F(title="Spot price from pair reserves used for valuation",
                        category=FindingCategory.ORACLE,
                        description="price() reads a manipulable spot value used in value(); flash-loan manipulable",
                        evidence="return amt * price();",
                        line_start=_line_of(ORACLE_SRC, "return amt * price();"), file_path="C.sol")]),
    # 8. Signature replay
    Case("signature_vuln", "signature_replay", "vulnerable", {"C.sol": SIG_SRC},
         candidates=[_F(title="Signature replay: no nonce or chainid",
                        category=FindingCategory.ACCESS_CONTROL,
                        description="exec() accepts a signature without a nonce, allowing replay",
                        evidence="address signer = ecrecover(keccak256(abi.encode(to, amt)), v, r, s);",
                        line_start=_line_of(SIG_SRC, "ecrecover"), file_path="C.sol")]),
    # 9. Token integration
    Case("token_vuln", "token_integration", "vulnerable", {"C.sol": TOKEN_SRC},
         candidates=[_F(title="Unchecked ERC20 transfer return (no-return token)",
                        category=FindingCategory.TOKEN,
                        description="transfer return value is ignored; non-standard tokens return no bool",
                        evidence="IERC20(tok).transfer(to, a);",
                        line_start=_line_of(TOKEN_SRC, "IERC20(tok).transfer"), file_path="C.sol")]),
    Case("vendored_standard_trap", "token_integration", "secure", {"C.sol": VENDOR_SRC},
         candidates=[_F(title="Standard ERC20 approve allowance race",
                        category=FindingCategory.TOKEN,
                        description="standard ERC20 approve/transferFrom allowance race semantics",
                        evidence="allowance[msg.sender][sp] = v;",
                        file_path="@openzeppelin/contracts/token/ERC20/ERC20.sol",
                        line_start=5)],
         expect_actionable=False, expect_rule="al0_standard_behavior"),
    # 10. Denial of service
    Case("dos_vuln", "denial_of_service", "vulnerable", {"C.sol": DOS_SRC},
         candidates=[_F(title="DoS: unbounded loop with push payment", category=FindingCategory.LOGIC_ERROR,
                        description="airdrop() loops over all users and pushes ETH; one revert blocks all",
                        evidence="payable(users[i]).transfer(1);",
                        line_start=_line_of(DOS_SRC, "payable(users[i]).transfer(1);"),
                        file_path="C.sol")]),
    # 11. Cross-contract
    Case("cross_contract_vuln", "cross_contract", "vulnerable", {"C.sol": XCONTR_SRC},
         candidates=[_F(title="External call to unresolved contract after state write",
                        category=FindingCategory.UNHANDLED_EXCEPTION,
                        description="a call to an external contract assumed to succeed; return only on ok",
                        evidence='(bool ok, ) = ext.call("");',
                        line_start=_line_of(XCONTR_SRC, "ext.call"), file_path="C.sol")]),
    # 12. Business logic
    Case("business_logic_vuln", "business_logic", "vulnerable", {"C.sol": LOGIC_SRC},
         candidates=[_F(title="Share/asset accounting mismatch on withdraw", category=FindingCategory.LOGIC_ERROR,
                        description="withdraw burns shares without redeeming assets at the correct rate; rounding loss",
                        evidence="shares[msg.sender] -= s;",
                        line_start=_line_of(LOGIC_SRC, "shares[msg.sender] -= s;"), file_path="C.sol")]),
    # 13. False-positive traps (misc)
    Case("readonly_trap", "false_positive_trap", "secure", {"C.sol": VIEW_SRC},
         candidates=[_F(title="getFee() allows an upgrade to change fees",
                        evidence="return fee;",
                        line_start=_line_of(VIEW_SRC, "return fee;"), file_path="C.sol")],
         expect_actionable=False, expect_rule="ro0_readonly_contradiction"),
    Case("internal_unreachable_trap", "false_positive_trap", "secure", {"C.sol": INTERNAL_SRC},
         candidates=[_F(title="Unsafe state write in _orphan()",
                        evidence="x = v;", line_start=_line_of(INTERNAL_SRC, "_orphan"),
                        file_path="C.sol")],
         expect_actionable=False, expect_rule="ra0_internal_unreachable"),
    Case("compiler_warning_trap", "false_positive_trap", "secure", {"C.sol": ACCESS_SRC},
         candidates=[_F(title="solc version: pragma should be floating",
                        detector_id="solc-version", severity="low",
                        evidence="function setX(uint256 v) external { x = v; }",
                        line_start=_line_of(ACCESS_SRC, "x = v;"), file_path="C.sol")],
         expect_actionable=False),
    Case("transfer_rollback_trap", "false_positive_trap", "secure", {"C.sol": WETH_SRC},
         candidates=[_F(title="Balance persists after failed ETH transfer",
                        description="the balance is deducted and remains deducted when transfer() fails",
                        evidence="msg.sender.transfer(wad);",
                        line_start=_line_of(WETH_SRC, "msg.sender.transfer(wad);"),
                        file_path="C.sol")],
         compiler="v0.4.18", expect_actionable=False,
         expect_rule="evm0_transfer_reverts_rollback"),
    # 14. Solidity version / EVM rollback semantics (vulnerable w/ attack path)
    Case("version_reachable_vuln", "solidity_version", "vulnerable", {"C.sol": OVERFLOW_TOOL_SRC},
         candidates=[_F(title="Unchecked arithmetic reachable with attacker input",
                        category=FindingCategory.ARITHMETIC,
                        description="amount is attacker-controlled; overflow in balanceOf lets an attacker inflate balances and drain funds",
                        evidence="balanceOf[rs[i]] += amount;",
                        line_start=_line_of(OVERFLOW_TOOL_SRC, "balanceOf[rs[i]] += amount;"),
                        file_path="C.sol")]),
]


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------

def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(1 for r in rows if r["expected"] and r["predicted"])
    fp = sum(1 for r in rows if not r["expected"] and r["predicted"])
    fn = sum(1 for r in rows if r["expected"] and not r["predicted"])
    tn = sum(1 for r in rows if not r["expected"] and not r["predicted"])
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec and rec and prec + rec) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {
        "n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(prec, 4) if prec is not None else None,
        "recall": round(rec, 4) if rec is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "false_positive_rate": round(fpr, 4) if fpr is not None else None,
    }


def _reproducibility_rate() -> float:
    """Fraction of the reference high-impact scenarios reproduced by REAL EVM
    execution (1.0 when the vulnerable scenario reproduces and the CEI-correct
    control does not; 0.0 otherwise / when no backend is installed)."""
    try:
        from agentsafe.validation.evm_poc import (
            evm_backend_available,
            run_reentrancy_poc,
            run_reentrancy_poc_safe,
        )
    except Exception:
        return 0.0
    if not evm_backend_available():
        return 0.0
    try:
        vuln = run_reentrancy_poc()
        ctrl = run_reentrancy_poc_safe()
    except Exception:
        return 0.0
    return 1.0 if (vuln.impact_demonstrated and not ctrl.impact_demonstrated) else 0.0


def evaluate(cases: list[Case] | None = None) -> dict[str, Any]:
    cases = cases or CASES
    rows: list[dict[str, Any]] = []
    for c in cases:
        try:
            final = decide(
                list(c.candidates), c.source,
                tool_findings=list(c.tool_findings), compiler=c.compiler,
            )
            predicted = any(f.status in ACTIONABLE for f in final)
            rule = None
            for f in final:
                rule = (f.metadata.get("validation") or {}).get("rule") or rule
                rule = (f.metadata.get("challenge") or {}).get("rule") or rule
            rows.append({
                "id": c.id, "category": c.category, "kind": c.kind,
                "expected": bool(c.expect_actionable), "predicted": predicted,
                "rule": rule, "expected_rule": c.expect_rule,
                "statuses": [f.status.value for f in final],
                "ok": predicted == c.expect_actionable
                and (c.expect_rule is None or (rule or "").startswith(c.expect_rule)),
            })
        except Exception as exc:  # an execution failure must be recorded, not hidden
            rows.append({
                "id": c.id, "category": c.category, "kind": c.kind,
                "expected": bool(c.expect_actionable), "predicted": False,
                "rule": None, "expected_rule": c.expect_rule,
                "statuses": [], "error": f"{type(exc).__name__}: {exc}", "ok": False,
            })

    by_cat: dict[str, dict[str, Any]] = {}
    for cat in sorted({r["category"] for r in rows}):
        by_cat[cat] = metrics([r for r in rows if r["category"] == cat])
    return {
        "cases": rows,
        "aggregate": metrics(rows),
        "by_category": by_cat,
        "n_errors": sum(1 for r in rows if r.get("error")),
        "n_categories": len(by_cat),
        # fraction of high-impact reference scenarios reproduced by REAL EVM
        # execution (0.0 when no EVM backend is installed).
        "confirmed_reproducibility_rate": _reproducibility_rate(),
    }
