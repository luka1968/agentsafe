"""Section 5 — attacker simulation and exploitability gating.

Pins the exploitability contract:

- the attacker model is derived from real reachability + intel (caller,
  permissions, capital, multi-tx, external dependency, sequence);
- an infeasible model (unreachable code, unavailable permissions, or a claim
  that assumes an unavailable external contract's behavior) can NEVER remain
  CONFIRMED;
- a genuinely open external entry keeps its confirmation and records a
  feasible model;
- unknown stays unknown (no invented execution order or economic claim).
"""

from __future__ import annotations

from agentsafe.agents.adversarial import AdversarialVerifier
from agentsafe.agents.attacker import build_attacker_model
from agentsafe.agents.reachability import build_reachability
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.schemas import Finding, FindingCategory, FindingStatus

OPEN_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract V {",                                              # 2
        "    uint256 public balances;",                              # 3
        "    function deposit() external payable {",                 # 4
        "        balances += msg.value;",                            # 5
        "    }",                                                     # 6
        "}",                                                         # 7
    ]
)
GATED_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract G {",                                              # 2
        "    address private owner;",                                # 3
        "    uint256 public balances;",                              # 4
        "    function setBal(uint256 v) external onlyOwner {",       # 5
        "        balances = v;",                                     # 6
        "    }",                                                     # 7
        "}",                                                         # 8
    ]
)
INTERNAL_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract I {",                                              # 2
        "    uint256 private x;",                                    # 3
        "    function poke() external { x = 1; }",                   # 4
        "    function _orphan(uint256 v) internal { x = v; }",       # 5
        "}",                                                         # 6
    ]
)
UNRESOLVED_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract C {",                                              # 2
        "    address private token;",                                # 3
        "    function pay(address to, uint256 amt) external {",      # 4
        "        token.transfer(to, amt);",                          # 5
        "    }",                                                     # 6
        "}",                                                         # 7
    ]
)


def _line_of(src: str, needle: str) -> int:
    for i, ln in enumerate(src.splitlines(), start=1):
        if needle in ln:
            return i
    raise AssertionError(needle)


def _ctx(src: str, path: str = "C.sol"):
    intel = extract_contract_intel({path: src})
    model = build_reachability({path: src}, intel=intel)
    return intel, model


def _finding(**kw) -> Finding:
    base = dict(
        title="State corruption", severity="high", status=FindingStatus.POTENTIAL,
        source=["test"], description="a state value is overwritten",
        evidence="balances = v;", file_path="C.sol", line_start=1,
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# attacker model
# ---------------------------------------------------------------------------

class TestAttackerModel:
    def test_open_payable_entry_is_feasible_for_ordinary_eoa(self):
        intel, model = _ctx(OPEN_SRC)
        f = _finding(file_path="C.sol", line_start=_line_of(OPEN_SRC, "balances += msg.value"))
        am = build_attacker_model(f, model, intel=intel, paths=[])
        assert am.ordinary_external_account == "yes"
        assert am.feasible == "yes"
        assert any("msg.value" in c for c in am.capital_required)
        assert am.flash_loan_relevant == "possible"
        assert am.sequence  # derived from the body, not invented

    def test_gated_entry_requires_permission_and_is_infeasible(self):
        intel, model = _ctx(GATED_SRC)
        f = _finding(file_path="C.sol", line_start=_line_of(GATED_SRC, "balances = v;"))
        am = build_attacker_model(f, model, intel=intel)
        assert am.ordinary_external_account == "no"
        assert any("onlyOwner" in p for p in am.permissions)
        assert am.blockers and am.feasible == "no"

    def test_unreachable_internal_function_is_infeasible(self):
        intel, model = _ctx(INTERNAL_SRC)
        f = _finding(file_path="C.sol", line_start=_line_of(INTERNAL_SRC, "_orphan"))
        am = build_attacker_model(f, model, intel=intel)
        assert am.ordinary_external_account == "no"
        assert any("not reachable" in b for b in am.blockers)
        assert am.feasible == "no"

    def test_claim_assuming_unavailable_external_behavior_is_blocked(self):
        intel, model = _ctx(UNRESOLVED_SRC)
        line = _line_of(UNRESOLVED_SRC, "token.transfer")
        neutral = _finding(file_path="C.sol", line_start=line)
        am_neutral = build_attacker_model(neutral, model, intel=intel)
        assert am_neutral.external_dependencies  # recorded
        assert not am_neutral.blockers  # a plain external call is not an assumption

        assuming = _finding(
            title="Mint assumes the price oracle returns a fresh value",
            description="the code assumes the oracle returns a valid price",
            file_path="C.sol", line_start=line,
        )
        am = build_attacker_model(assuming, model, intel=intel)
        assert "yes" in am.external_behavior_required
        assert am.blockers and am.feasible == "no"

    def test_unknown_model_when_no_source_structure(self):
        f = _finding(file_path="C.sol", line_start=1)
        am = build_attacker_model(f, None)
        assert am.caller == "unknown"
        assert am.feasible == "unknown"
        assert am.economic_worth == "unknown"


# ---------------------------------------------------------------------------
# confirmation gate
# ---------------------------------------------------------------------------

class TestConfirmationGate:
    def test_confirmed_gated_finding_cannot_stay_confirmed(self):
        intel, _model = _ctx(GATED_SRC)
        f = _finding(
            status=FindingStatus.CONFIRMED,
            file_path="C.sol", line_start=_line_of(GATED_SRC, "balances = v;"),
        )
        res = AdversarialVerifier().review(
            [], [f], {"C.sol": GATED_SRC}, False, intel=intel, paths=[]
        )
        out = res.llm_findings[0]
        assert out.status is FindingStatus.NEEDS_MANUAL_REVIEW
        assert out.status is not FindingStatus.CONFIRMED
        assert out.metadata["challenge"]["rule"] == "att0_infeasible_attacker_model"
        assert res.needs_review == 1
        assert "attacker_model" in out.metadata

    def test_confirmed_open_finding_keeps_confirmation(self):
        intel, _model = _ctx(OPEN_SRC)
        f = _finding(
            status=FindingStatus.CONFIRMED,
            file_path="C.sol",
            line_start=_line_of(OPEN_SRC, "balances += msg.value"),
            title="Unchecked arithmetic in deposit",
            description="balances can be overwritten without limit",
        )
        res = AdversarialVerifier().review(
            [], [f], {"C.sol": OPEN_SRC}, False, intel=intel, paths=[]
        )
        out = res.llm_findings[0]
        assert out.status is FindingStatus.CONFIRMED
        assert out.metadata["attacker_model"]["feasible"] == "yes"

    def test_attacker_model_attached_to_every_actionable_finding(self):
        intel, _model = _ctx(GATED_SRC)
        f = _finding(
            status=FindingStatus.POTENTIAL,
            file_path="C.sol", line_start=_line_of(GATED_SRC, "balances = v;"),
            category=FindingCategory.ACCESS_CONTROL,
        )
        res = AdversarialVerifier().review(
            [], [f], {"C.sol": GATED_SRC}, False, intel=intel, paths=[]
        )
        assert "attacker_model" in res.llm_findings[0].metadata
