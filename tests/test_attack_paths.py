"""Stage C — autonomous attack-path discovery.

Pins:
- the Stage-7 hypotheses actually REACH the agents (renderers accept the dict
  form the agent material carries - previously an AttributeError silently
  dropped every path and invariant);
- each path carries the Stage-C attributes (permissions, state transitions,
  external dependencies, attacker-controlled inputs, capital, impact,
  cross-contract, transaction count);
- multi-transaction sequences are marked as such;
- attacker reachability is determined per path (a fully authorization-gated
  entry is NOT attacker-reachable).
"""

from __future__ import annotations

from agentsafe.agents.attack_paths import annotate_attack_paths
from agentsafe.agents.reachability import build_reachability
from agentsafe.intel.extract import extract_contract_intel
from agentsafe.intel.invariants import InvariantRecord, render_invariants
from agentsafe.intel.paths import AttackPath, enumerate_attack_paths, render_paths

VAULT_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract V {",                                              # 2
        "    uint256 public balances;",                              # 3
        "    function deposit() external payable {",                 # 4
        "        balances = msg.value;",                             # 5
        "    }",                                                     # 6
        "    function peek() external view returns (uint256) {",     # 7
        "        return balances;",                                  # 8
        "    }",                                                     # 9
        "    function payout(address to) external {",                # 10
        "        _send(to);",                                        # 11
        "    }",                                                     # 12
        "    function _send(address to) internal {",                 # 13
        "        uint256 b = balances;",                             # 14
        '        (bool ok, ) = to.call{value: b}("");',              # 15
        '        require(ok, "failed");',                            # 16
        "    }",                                                     # 17
        "}",                                                         # 18
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
        "    function peek() external view returns (uint256) {",     # 8
        "        return balances;",                                  # 9
        "    }",                                                     # 10
        "}",                                                         # 11
    ]
)

XCONTRACT_SRC = "\n".join(
    [
        "pragma solidity ^0.8.0;",                                   # 1
        "contract Base {",                                           # 2
        "    function _send(address to) internal {",                 # 3
        '        (bool ok, ) = to.call{value: 1}("");',              # 4
        '        require(ok, "x");',                                 # 5
        "    }",                                                     # 6
        "}",                                                         # 7
        "contract Child is Base {",                                  # 8
        "    function f(address to) external {",                     # 9
        "        _send(to);",                                        # 10
        "    }",                                                     # 11
        "}",                                                         # 12
    ]
)


# ---------------------------------------------------------------------------
# regression: the hypotheses must reach the agents (dict-form rendering)
# ---------------------------------------------------------------------------

class TestHypothesesRenderFromDicts:
    def test_render_paths_accepts_dict_form(self):
        d = AttackPath(functions=["V.deposit", "V.peek"], origin="multi_tx_sequence",
                       transaction_count=2).to_dict()
        out = render_paths([d])
        assert "multi_tx_sequence" in out
        assert "attacker_reachable" in out
        assert "V.deposit -> V.peek" in out

    def test_render_invariants_accepts_dict_form(self):
        d = InvariantRecord(statement="balances <= totalDeposits",
                            invariant_type="accounting").to_dict()
        out = render_invariants([d])
        assert "balances <= totalDeposits" in out


# ---------------------------------------------------------------------------
# path attributes
# ---------------------------------------------------------------------------

class TestPathAttributes:
    def _paths(self):
        intel = extract_contract_intel({"V.sol": VAULT_SRC})
        return enumerate_attack_paths(intel)

    def test_state_write_path_records_transition_and_permissions(self):
        paths = self._paths()
        followups = [p for p in paths if p.origin == "state_var_followup"]
        assert followups
        assert any(
            any("writes balances" in t for t in p.state_transitions)
            for p in followups
        )

    def test_eth_sink_path_records_impact_and_inputs(self):
        paths = self._paths()
        sink = [p for p in paths if p.origin == "sink_enumeration"]
        assert sink
        assert any("ETH transfer" in p.impact for p in sink)
        assert any(p.attacker_controlled_inputs for p in sink)

    def test_multi_transaction_sequence_is_marked(self):
        paths = self._paths()
        multi = [p for p in paths if p.origin == "multi_tx_sequence"]
        assert multi and all(p.transaction_count == 2 for p in multi)

    def test_cross_contract_path_is_flagged(self):
        intel = extract_contract_intel({"X.sol": XCONTRACT_SRC})
        paths = enumerate_attack_paths(intel)
        assert any(p.cross_contract for p in paths)

    def test_to_dict_includes_stage_c_fields(self):
        d = self._paths()[0].to_dict()
        for key in (
            "required_permissions", "state_transitions", "external_dependencies",
            "attacker_controlled_inputs", "capital_requirements", "impact",
            "cross_contract", "transaction_count", "attacker_reachable",
        ):
            assert key in d


# ---------------------------------------------------------------------------
# attacker reachability
# ---------------------------------------------------------------------------

class TestAttackerReachabilityAnnotation:
    def test_open_entry_path_is_attacker_reachable(self):
        intel = extract_contract_intel({"V.sol": VAULT_SRC})
        paths = [p.to_dict() for p in enumerate_attack_paths(intel)]
        enriched, counts = annotate_attack_paths(paths, {"V.sol": VAULT_SRC}, intel=intel)
        assert counts["attacker_reachable"] >= 1
        assert any(p["attacker_reachable"] == "yes" for p in enriched)

    def test_gated_entry_path_is_not_attacker_reachable(self):
        intel = extract_contract_intel({"G.sol": GATED_SRC})
        paths = [p.to_dict() for p in enumerate_attack_paths(intel)]
        # a path whose only external entry is onlyOwner must be marked "no"
        gated = [p for p in paths if p["entry_points"] == ["G.setBal"]]
        assert gated, "expected a path anchored on the onlyOwner setter"
        enriched, counts = annotate_attack_paths(gated, {"G.sol": GATED_SRC}, intel=intel)
        assert enriched[0]["attacker_reachable"] == "no"
        assert counts["gated"] >= 1

    def test_model_key_lookup_is_tri_state(self):
        model = build_reachability({"G.sol": GATED_SRC})
        assert model is not None
        assert model.key_attacker_reachable("G.setBal") == "no"
        assert model.key_attacker_reachable("G.peek") == "yes"
        assert model.key_attacker_reachable("Nonexistent.fn") == "unknown"
