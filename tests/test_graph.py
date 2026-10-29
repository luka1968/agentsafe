"""Tests: Contract Intelligence Layer (Stage 4) — graph.py + extract.py additions.

Covers: pragma extraction, missing-source tracking, call graph, state
dependency graph, state-change evidence, proxy classification, sink inventory.
All deterministic, derived from source (no LLM).
"""

from __future__ import annotations

from agentsafe.intel.extract import ContractIntel, extract_contract_intel
from agentsafe.intel.graph import (
    call_graph,
    classify_proxy_pattern,
    sink_inventory,
    state_change_evidence,
    state_dependency_graph,
)

VULN_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Ownable.sol";
import {ISwapRouter} from "./ISwapRouter.sol";

contract Vault is Ownable {
    mapping(address => uint256) public balances;
    uint256 public totalLocked;
    bool public paused;
    address public feeCollector;
    uint256 __gap;

    event Deposit(address indexed who, uint256 amount);

    constructor() Ownable() {
        balances[msg.sender] = 0;
    }

    modifier onlyOwner() {
        require(msg.sender == owner(), "not owner");
        _;
    }

    function deposit() external payable {
        unchecked { balances[msg.sender] += msg.value; }
        totalLocked += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] -= amount;
        totalLocked -= amount;
    }

    function setFeeCollector(address who) external onlyOwner {
        feeCollector = who;
    }

    function upgradeTo(address impl) external onlyOwner {
        address slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    }
}

interface ISwapRouter {
    function exactInputSingle(bytes calldata) external returns (uint256);
}
"""


def _intel() -> ContractIntel:
    return extract_contract_intel({"Vault.sol": VULN_SRC})


class TestPragmaAndMissing:
    def test_pragma_extracted(self):
        it = _intel()
        assert it.pragma, "pragma solidity should be captured"
        assert "^0.8.20" in it.pragma[0]

    def test_missing_sources_tracked(self):
        it = _intel()
        missing = set(it.missing_sources)
        assert "./Ownable.sol" in missing
        assert "./ISwapRouter.sol" in missing

    def test_interface_recorded(self):
        it = _intel()
        names = [c.name for c in it.contracts]
        assert "Vault" in names and "ISwapRouter" in names


class TestCallGraph:
    def test_internal_edges(self):
        it = _intel()
        g = call_graph(it)
        # deposit/unchecked writes; no cross fn call — ensure no phantom edge
        assert g.get("Vault.deposit", []) == []

    def test_external_call_edge_recorded(self):
        it = _intel()
        g = call_graph(it)
        # withdraw has msg.sender.call -> not a contract fn; no phantom edge
        assert "Vault.withdraw" in g
        assert not g["Vault.withdraw"]  # external .call is not a parsed fn


class TestStateDeps:
    def test_readers_writers(self):
        it = _intel()
        sdg = state_dependency_graph(it)
        key = "Vault.balances"
        assert key in sdg
        assert "Vault.deposit" in sdg[key]["writers"]
        assert "Vault.withdraw" in sdg[key]["writers"]
        assert "Vault.withdraw" in sdg[key]["readers"]
        # += reads the prior value -> deposit is BOTH reader and writer
        assert "Vault.deposit" in sdg[key]["readers"]


class TestStateChangeEvidence:
    def test_writes_with_ops(self):
        it = _intel()
        ev = state_change_evidence(it)
        withdraw_ev = ev.get("Vault.withdraw", [])
        ops = {(e.var, e.op) for e in withdraw_ev}
        assert ("balances", "rw") in ops
        assert ("totalLocked", "rw") in ops

    def test_deposit_evidence(self):
        it = _intel()
        ev = state_change_evidence(it)
        deposit_ev = ev.get("Vault.deposit", [])
        assert any(e.var == "balances" for e in deposit_ev)


class TestProxyPattern:
    def test_uups_detected_from_slot(self):
        it = _intel()
        pats = classify_proxy_pattern(it)
        vault = next(p for p in pats if p.contract == "Vault")
        assert vault.kind in ("uups", "transparent")
        assert vault.evidence  # auditable classification

    def test_storage_gap_detected(self):
        it = _intel()
        vault = next(p for p in classify_proxy_pattern(it)
                     if p.contract == "Vault")
        assert vault.storage_gap_present  # __gap in state vars


class TestSinkInventory:
    def test_sinks_capture_dangerous_ops(self):
        it = _intel()
        sinks = {s["fn"]: s for s in sink_inventory(it)}
        w = sinks.get("Vault.withdraw")
        assert w is not None
        assert "ether_transfer" in w["ops"]
        assert "arithmetic" in w["ops"]
        d = sinks.get("Vault.deposit")
        assert d is not None
        assert "unchecked_arith" in d["ops"]

    def test_no_phantom_sinks(self):
        it = _intel()
        sinks = sink_inventory(it)
        for s in sinks:
            assert s["ops"], "sink must have at least one op"
