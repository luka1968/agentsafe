"""Stage D — deep specialist analysis.

Pins the Stage-D additions and fixes:

- two new specialists (oracle, cross-contract) exist, are wired into the
  registry AND the classifier's SPECIALISTS set, and carry KB profiles;
- the classifier triggers them on the relevant evidence (oracle vocabulary,
  external calls / interfaces / unresolved externals);
- the intel brief is genuinely focus-tailored per specialist (previously only
  the access-control agent got tailored intel; every other agent fell through
  to access-control facets);
- prompt-level markdown/legacy focus prose still resolves.
"""

from __future__ import annotations

from agentsafe.agents.classification import SPECIALISTS, classify_contract
from agentsafe.agents.specialists import (
    SPECIALIST_REGISTRY,
    CrossContractAgent,
    OracleAgent,
)
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.intel.render import render_intel_brief


def test_registry_and_classifier_are_in_sync_with_new_specialists():
    assert set(SPECIALISTS) == set(SPECIALIST_REGISTRY.keys())
    assert "oracle" in SPECIALIST_REGISTRY
    assert "cross_contract" in SPECIALIST_REGISTRY
    assert OracleAgent.profile == "oracle"
    assert CrossContractAgent.profile == "cross_contract"
    assert OracleAgent.name == "oracle"
    assert CrossContractAgent.name == "cross_contract"


class TestClassificationTriggers:
    def test_oracle_specialist_triggered_on_price_surface(self):
        p = classify_contract(None, "uint p = oracle.latestRoundData();")
        assert p.triggers.get("oracle") == "deep"

    def test_cross_contract_triggered_on_external_call(self):
        p = classify_contract(None, "token.transfer(to, amt);")
        assert p.triggers.get("cross_contract") == "deep"

    def test_cross_contract_basic_on_interface_only(self):
        p = classify_contract(None, "interface IERC20 { function x() external; }")
        assert p.triggers.get("cross_contract") == "basic"

    def test_cross_contract_triggered_by_unresolved_externals(self):
        intel = extract_contract_intel(
            {"A.sol": "contract A { address t; function p() external { t.ping(); } }"}
        )
        p = classify_contract(intel, "")
        assert "cross_contract" in p.triggers

    def test_plain_arithmetic_contract_triggers_neither(self):
        p = classify_contract(None, "contract A { uint x; function f() external { x += 1; } }")
        assert "oracle" not in p.triggers
        assert "cross_contract" not in p.triggers


INTEL_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract C {",
        "    address private owner;",
        "    uint256 public balances;",
        "    function deposit() external payable { balances += msg.value; }",
        "    function adminSet(uint256 v) external onlyOwner { balances = v; }",
        "    function pay(address to) external {",
        '        (bool ok, ) = to.call{value: 1}("");',
        '        require(ok, "x");',
        "    }",
        "}",
    ]
)


class TestFocusTailoredIntelBrief:
    def _intel(self):
        return extract_contract_intel({"C.sol": INTEL_SRC})

    def test_access_control_gets_privileged_but_not_transfers(self):
        brief = render_intel_brief(self._intel(), "access_control")
        assert "PRIVILEGED FNS" in brief
        assert "TRANSFER SITES" not in brief

    def test_accounting_gets_transfer_sites(self):
        brief = render_intel_brief(self._intel(), "accounting")
        assert "TRANSFER SITES" in brief

    def test_reentrancy_gets_transfers_and_state(self):
        brief = render_intel_brief(self._intel(), "reentrancy")
        assert "TRANSFER SITES" in brief
        assert "STATE ACCESS MAP" in brief

    def test_arithmetic_gets_arithmetic_facet(self):
        brief = render_intel_brief(self._intel(), "arithmetic")
        assert "ARITHMETIC" in brief

    def test_legacy_focus_prose_still_resolves(self):
        brief = render_intel_brief(self._intel(), "Fund flow and value-transfer analysis")
        assert "TRANSFER SITES" in brief
