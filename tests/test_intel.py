"""Tests: contract intelligence layer (extract.py, render.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsafe.intel import (
    ContractIntel,
    enrich_from_slither_json,
    extract_contract_intel,
    render_intel_brief,
    render_kb_snippets,
)

VAULT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Ownable {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }
    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}

contract Vault is Ownable {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    IERC20 public token;
    bool public paused;

    event Deposit(address indexed who, uint256 amount);
    event Withdrawn(address indexed who, uint256 amount);

    constructor(IERC20 t) { token = t; owner = msg.sender; }

    function deposit(uint256 amount) external {
        require(!paused, "paused");
        token.transferFrom(msg.sender, address(this), amount);
        uint256 s = amount * totalShares / 1e18;
        shares[msg.sender] += s;
        totalShares += s;
        emit Deposit(msg.sender, amount);
    }

    function withdraw(uint256 s) external {
        uint256 due = s * 1e18 / totalShares;
        shares[msg.sender] -= s;
        token.transfer(msg.sender, due);
        emit Withdrawn(msg.sender, due);
    }

    function sweep(address to) external onlyOwner {
        token.transfer(to, token.balanceOf(address(this)));
    }

    function emergency() external payable {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "fail");
    }
}
"""

PROXY = """\
pragma solidity ^0.8.20;
contract ERC1967Utils {
    function _setImplementation(address impl) internal {
        // slot 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        assembly { sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, impl) }
    }
    function upgradeToAndCall(address i, bytes memory d) internal {
        _setImplementation(i);
    }
}
contract FraxProxy is ERC1967Utils {
    function initialize(address admin) public {
        upgradeToAndCall(admin, "");
    }
}
"""


class TestExtractor:
    def test_extracts_contracts_and_inheritance(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        names = {c.name for c in intel.contracts}
        assert {"IERC20", "Ownable", "Vault"} <= names
        vault = next(c for c in intel.contracts if c.name == "Vault")
        assert "Ownable" in vault.bases

    def test_state_vars_and_events(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        vault = next(c for c in intel.contracts if c.name == "Vault")
        for sv in ("shares", "totalShares", "token", "paused"):
            assert sv in vault.state_vars
        assert {"Deposit", "Withdrawn"} <= set(vault.events)

    def test_function_signatures(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        vault = next(c for c in intel.contracts if c.name == "Vault")
        fns = {f.name: f for f in vault.functions}
        assert fns["deposit"].visibility == "external"
        assert fns["deposit"].mutability == ""
        assert fns["emergency"].mutability == "payable"
        assert "onlyOwner" in fns["sweep"].modifiers
        assert fns["sweep"].line_start > 0

    def test_read_write_sets(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        assert "deposit" in intel.writers_of_state("totalShares")
        assert "withdraw" in intel.readers_of_state("totalShares")
        assert "transferOwnership" in intel.writers_of_state("owner")

    def test_call_edges_and_transfer_sites(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        vault = next(c for c in intel.contracts if c.name == "Vault")
        emergency = next(f for f in vault.functions if f.name == "emergency")
        assert emergency.ether_calls == 1
        assert "fail" in "".join(emergency.guards)
        sweep = next(f for f in vault.functions if f.name == "sweep")
        assert "transfer" in sweep.token_calls

    def test_call_graph_internal_edges(self):
        intel = extract_contract_intel({"P.sol": PROXY})
        assert intel.callers_of("_setImplementation") == ["upgradeToAndCall"]

    def test_arithmetic_and_unchecked(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        vault = next(c for c in intel.contracts if c.name == "Vault")
        deposit = next(f for f in vault.functions if f.name == "deposit")
        assert deposit.arithmetic & {"*", "+", "/"}

    def test_proxy_pattern_and_privileged_and_initializer(self):
        intel = extract_contract_intel({"P.sol": PROXY, "Vault.sol": VAULT})
        assert any("ERC1967Utils" in h or "FraxProxy" in h for h in intel.proxy_hints)
        assert any("initialize" in p for p in intel.initializer_functions)
        assert any("sweep" in p or "transferOwnership" in p
                   for p in intel.privileged_functions)
        assert any("upgradeToAndCall" in p for p in intel.privileged_functions)

    def test_unresolved_externals_tracked_not_invented(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        # token is an interface-typed state var; its implementation body is
        # NOT in this source set -> must be flagged unresolved.
        assert any("token." in u for u in intel.unresolved_externals)
        iface = next(c for c in intel.contracts if c.name == "IERC20")
        assert iface.functions == []

    def test_interface_and_empty_input(self):
        intel = extract_contract_intel({})
        assert intel.extraction_warnings
        assert intel.contracts == []
        intel2 = extract_contract_intel({"x.sol": "assembly { }"})
        assert any("no top-level contract" in w for w in intel2.extraction_warnings)

    def test_line_numbers_stable(self):
        intel1 = extract_contract_intel({"V.sol": VAULT})
        intel2 = extract_contract_intel({"V.sol": VAULT})
        v1 = [c.to_dict() for c in intel1.contracts]
        v2 = [c.to_dict() for c in intel2.contracts]
        assert v1 == v2

    def test_comments_do_not_break_lines(self):
        src = "contract A {\n// x = y\nuint256 public z;\n}"
        intel = extract_contract_intel({"A.sol": src})
        a = intel.contracts[0]
        assert "z" in a.state_vars


class TestSlitherEnrichment:
    def test_enrich_merges_detectors(self):
        intel = ContractIntel()
        enrich_from_slither_json(
            intel,
            '{"results":{"detectors":[{"check":"reentrancy-eth","impact":"High",'
            '"confidence":"Medium","description":"Vault.withdraw reentrant call"}]}}')
        assert intel.slither_detectors[0]["check"] == "reentrancy-eth"
        assert intel.to_dict()["slither_detector_count"] == 1

    def test_enrich_bad_json_is_warning(self):
        intel = ContractIntel()
        enrich_from_slither_json(intel, "not json{")
        assert any("unparsable" in w for w in intel.extraction_warnings)


class TestRender:
    def test_brief_is_bounded_and_honest(self):
        intel = extract_contract_intel({"Vault.sol": VAULT, "P.sol": PROXY})
        brief = render_intel_brief(intel, "fund flow and value-transfer analysis")
        assert len(brief) <= 2400
        assert "UNRESOLVED" in brief or "token." in brief
        assert "STATE ACCESS MAP" in brief

    def test_brief_focus_specific(self):
        intel = extract_contract_intel({"Vault.sol": VAULT})
        ac = render_intel_brief(intel, "Access control and privilege analysis")
        ff = render_intel_brief(intel, "Fund flow and value-transfer analysis")
        assert "PRIVILEGED FNS" in ac
        assert "TRANSFER SITES" in ff

    def test_brief_none_intel(self):
        assert render_intel_brief(None, "x") == "(no deterministic intel available for this audit)"

    def test_kb_snippets_force_applicability(self):
        recs = [{
            "id": "KB-2025-001", "category": "reentrancy",
            "protocol_type": "vault", "mechanism": "external call before state update",
            "root_cause": "CEI violation", "preconditions": ["eth to attacker"],
            "impact": "drain", "remediation": "CEI + guard",
            "source": "rekt.news", "url": "https://rekt.news/x/",
        }]
        out = render_kb_snippets(recs)
        assert "MUST explicitly decide" in out
        assert "KB-2025-001" in out
        assert render_kb_snippets([]) == "(no relevant knowledge-base records)"

    def test_kb_snippet_budget(self):
        recs = [{
            "id": f"R{i}", "category": "x", "protocol_type": "y",
            "mechanism": "m" * 800, "root_cause": "r" * 800,
            "preconditions": ["p" * 200], "impact": "i" * 800,
            "remediation": "x" * 800, "source": "s", "url": "u",
        } for i in range(4)]
        assert len(render_kb_snippets(recs)) <= 1600
