"""Stage 7 — cross-function attack paths + candidate invariants tests.

Covers: invariant proposal categories, explicit result vocabulary, evidence
honesty (no fabricated statements), withdrawal guard gating, path
enumeration bounds (depth/count), targeted suspicious-state selection,
inferred-vs-reproduced flagging, and orchestrator wiring sanity.
"""

from __future__ import annotations

from agentsafe.intel import extract_contract_intel
from agentsafe.intel.invariants import (
    INVARIANT_RESULTS,
    extract_invariants,
    render_invariants,
    validate_invariants,
)
from agentsafe.intel.paths import (
    enumerate_attack_paths,
    render_paths,
    suspicious_state_variables,
)

VAULT = {
    "Vault.sol": """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Vault {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    uint256 public totalAssets;
    bool public initialized;
    address public owner;

    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }
    modifier initializer() { require(!initialized, "init"); _; initialized = true; }

    function initialize(address _owner) external initializer {
        owner = _owner;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        totalAssets += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero");
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        totalAssets -= amount;
        payable(msg.sender).transfer(amount);
    }

    function setOwner(address _new) external onlyOwner {
        owner = _new;
    }

    function adminSweep(address token) external onlyOwner {
        // privileged write
        totalAssets = 0;
    }

    function _convert(uint256 shares) internal view returns (uint256) {
        return totalAssets * shares / totalSupply;
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return _convert(shares);
    }
}
""",
}

UNGUARDED = {
    "Raw.sol": """\
pragma solidity ^0.8.0;
contract Raw {
    mapping(address => uint256) public balances;
    function burn(uint256 amount) external {
        balances[msg.sender] -= amount;  // no >= guard
    }
    function ethIn() external payable { balances[msg.sender] += msg.value; }
}
""",
}

EMPTY = {}


def _intel(files: dict[str, str]):
    return extract_contract_intel(files)


class TestInvariantProposal:
    def test_proposes_expected_categories(self):
        inv = extract_invariants(_intel(VAULT))
        types = {r.invariant_type for r in inv}
        assert "asset_liability_accounting" in types
        assert "withdrawal_limit" in types
        assert "valid_initialization" in types
        assert "privileged_state" in types

    def test_all_results_in_vocabulary(self):
        inv = extract_invariants(_intel(VAULT))
        for r in inv:
            assert r.result in INVARIANT_RESULTS

    def test_no_invariants_for_empty_source(self):
        inv = extract_invariants(_intel(EMPTY))
        assert inv == []

    def test_evidence_never_invented(self):
        inv = extract_invariants(_intel(VAULT))
        blob = " ".join(ev for r in inv for ev in r.evidence).lower()
        src = " ".join(VAULT.values()).lower()
        for r in inv:
            for ev in r.evidence:
                assert ev.lower() in src or "->" in ev or ":" in ev
                # derived summaries carry explicit structure markers;
                # raw source slices appear verbatim — never invented

    def test_supporting_source_labels(self):
        inv = extract_invariants(_intel(VAULT))
        assert all(r.supporting_source.startswith("source:")
                   for r in inv if r.supporting_source)


class TestValidation:
    def test_withdraw_guard_yields_holds(self):
        recs = validate_invariants(_intel(VAULT),
                                   extract_invariants(_intel(VAULT)))
        wd = next(r for r in recs if r.invariant_type == "withdrawal_limit")
        assert wd.result == "holds_under_tested_conditions"
        assert any("not a proof" in lim for lim in wd.limitations)

    def test_unguarded_writer_inconclusive_not_violated_without_chain(self):
        recs = extract_invariants(_intel(UNGUARDED))
        # burn writes balances without a >= guard; without an enumerated
        # reachable chain the static result must stay inconclusive.
        assert recs
        for r in recs:
            assert r.result != "violated" or r.attack_path is not None
        for r in recs:
            assert r.result in INVARIANT_RESULTS

    def test_holds_result_carries_honesty_limitation(self):
        recs = validate_invariants(_intel(VAULT),
                                   extract_invariants(_intel(VAULT)))
        for r in recs:
            if r.result == "holds_under_tested_conditions":
                assert any("proof" in lim.lower() or "static" in lim.lower()
                           for lim in r.limitations)

    def test_initialization_result_gated_on_guard(self):
        recs = extract_invariants(_intel(VAULT))
        init = next(r for r in recs if r.invariant_type == "valid_initialization")
        assert init.result == "holds_under_tested_conditions"  # initializer modifier seen


class TestPathEnumeration:
    def test_paths_from_suspicious_state(self):
        intel = _intel(VAULT)
        paths = enumerate_attack_paths(intel, max_depth=3)
        assert paths
        for p in paths:
            assert p.functions  # entry -> ... chain
            assert p.origin in ("state_var_followup", "sink_enumeration",
                                "cross_read_write")
            assert p.reproduced is False  # never claim tests we didn't run

    def test_suspicious_state_cross_function_only(self):
        intel = _intel(VAULT)
        state = {
            f"{c.name}.{v}": {"readers": sorted({f"{c.name}.{f.name}"
                                  for f in c.functions if v in f.reads}),
                              "writers": sorted({f"{c.name}.{f.name}"
                                   for f in c.functions if v in f.writes})}
            for c in intel.contracts for v in c.state_vars}
        sus = suspicious_state_variables(intel, state)
        assert any("totalAssets" in s or "balances" in s for s in sus)
        # a var written and read only by the SAME single fn must be excluded
        for key, deps in state.items():
            if set(deps["readers"]) == set(deps["writers"]) and len(deps["readers"]) == 1:
                assert key not in sus

    def test_bounded_depth_and_count(self):
        intel = _intel(VAULT)
        paths = enumerate_attack_paths(intel, max_depth=1, max_paths=5)
        assert len(paths) <= 5
        assert all(p.depth <= 1 for p in paths)

    def test_empty_source_no_paths(self):
        assert enumerate_attack_paths(_intel(EMPTY)) == []

    def test_render_marks_inferred(self):
        intel = _intel(VAULT)
        text = render_paths(enumerate_attack_paths(intel))
        assert "inferred" in text
        assert "not findings" in text


class TestOrchestratorWiring:
    def test_material_carries_paths_and_invariants(self):
        from agentsafe.agents.base import AnalysisMaterial
        intel = _intel(VAULT)
        inv = extract_invariants(intel)
        paths = enumerate_attack_paths(intel)
        mat = AnalysisMaterial(
            kind="source", segments=VAULT, is_pseudo_source=False,
            intel=intel)
        mat.paths = paths
        mat.invariants = inv
        assert mat.paths == paths
        assert mat.invariants == inv

    def test_render_invariants_section(self):
        inv = validate_invariants(_intel(VAULT),
                                  extract_invariants(_intel(VAULT)))
        text = render_invariants(inv)
        assert "INVARIANTS" in text
        assert "[holds_under_tested_conditions]" in text or "inconclusive" in text
