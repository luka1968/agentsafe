"""Phase 5 context-aware retrieval tests.

Context is derived from deterministic intel + source text; matches are reported
as supporting signals, never invented.
"""

from __future__ import annotations

from agentsafe.intel.extract import ContractEntry, ContractIntel, FunctionIntel
from agentsafe.intel.render import render_kb_snippets
from agentsafe.knowledge.context import (
    context_query,
    derive_context,
    retrieve_for_agents,
)
from agentsafe.knowledge.rerank import context_factor


def _intel():
    vault = ContractEntry(
        name="Vault", kind="contract",
        state_vars={"totalShares": "uint256 public", "collateral": "uint256 public"},
        functions=[
            FunctionIntel(name="deposit", contract="Vault", visibility="public",
                          external_calls=["oracle.latestRoundData"],
                          token_calls=["transfer"], delegatecalls=0, unchecked=0,
                          ether_calls=0),
            FunctionIntel(name="withdraw", contract="Vault", visibility="external",
                          ether_calls=1),
        ])
    return ContractIntel(
        contracts=[vault], pragma=["^0.8.19"],
        privileged_functions=["Vault.withdraw [external/nonpayable]"],
        proxy_hints=["Vault.sol:Vault"])


TEXT = ("ERC20 vault deposit withdraw shares collateral oracle price feed "
        "delegatecall initialize")


class TestDeriveContext:
    def test_derives_all_signal_families(self):
        ctx = derive_context(_intel(), TEXT)
        assert ctx.solc == "0.8"
        assert "deposit" in ctx.functions and "withdraw" in ctx.functions
        assert "totalShares" in ctx.state_vars
        assert "oracle.latestRoundData" in ctx.external_calls
        assert "erc20" in ctx.token_standards
        assert "vault" in ctx.protocol_traits and "oracle" in ctx.protocol_traits
        assert "accounting" in ctx.categories
        # attack surface from intel: privileged function + ether-transfer site
        assert any("privileged:" in a for a in ctx.attack_surface)
        assert any("ether transfer" in a for a in ctx.attack_surface)

    def test_empty_intel_is_safe(self):
        ctx = derive_context(None, "")
        assert ctx.solc is None and ctx.functions == []
        assert ctx.to_match_dict()["solc"] is None


class TestContextQuery:
    def test_query_carries_contract_vocabulary(self):
        ctx = derive_context(_intel(), TEXT)
        q = context_query(ctx, "function deposit() { shares += x; }",
                          keywords=["reentrancy"], focus="accounting")
        assert "function deposit" in q
        assert "reentrancy" in q and "accounting" in q
        assert "totalShares" in q and "oracle.latestRoundData" in q


class TestContextFactor:
    def test_matches_state_var_and_category(self):
        ctx = derive_context(_intel(), TEXT)
        row = {"category": "accounting",
               "vulnerable_code": "totalShares = totalShares + shares;",
               "tags": ["oracle"]}
        factor, signals = context_factor(row, ctx.to_match_dict())
        assert factor > 1.0
        assert any("state variable totalShares" in s for s in signals)
        assert any("category accounting" in s for s in signals)

    def test_no_context_is_neutral(self):
        assert context_factor({"category": "oracle"}, None) == (1.0, [])


class _NeonLike:
    def __init__(self):
        self.captured = {}

    def search(self, query, *, focus="", limit=3, profile=None, solc=None,
               context=None):
        self.captured = {"query": query, "solc": solc, "context": context}
        return [{"id": "kb-1", "category": "oracle",
                 "description": "stale oracle price", "tags": ["oracle"]}]


class _FallbackKB:
    def __init__(self):
        self.called = False

    def search(self, query, *, focus="", limit=3, profile=None):
        self.called = True
        return [{"id": "jsonl-1", "category": "accounting"}]


class TestRetrieveForAgents:
    def test_uses_context_on_neon_store(self):
        ctx = derive_context(_intel(), TEXT)
        kb = _NeonLike()
        recs = retrieve_for_agents(kb, ctx, chunk="deposit shares",
                                   keywords=["oracle"], profile="oracle")
        assert kb.captured["solc"] == "0.8"
        assert kb.captured["context"]["state_vars"] == ctx.state_vars
        assert recs[0]["_retrieval"]["context_signals"]  # annotated

    def test_falls_back_on_plain_kb(self):
        ctx = derive_context(_intel(), TEXT)
        kb = _FallbackKB()
        recs = retrieve_for_agents(kb, ctx, chunk="deposit", profile="oracle")
        assert kb.called and recs[0]["id"] == "jsonl-1"


class TestRendererContextLine:
    def test_renders_context_match_line(self):
        out = render_kb_snippets([{
            "id": "kb-1", "category": "oracle", "mechanism": "m",
            "_retrieval": {"context_signals": ["state variable totalShares",
                                               "category accounting"]}}])
        assert "target-context match:" in out
        assert "state variable totalShares" in out

    def test_no_context_no_line(self):
        out = render_kb_snippets([{"id": "kb-1", "category": "oracle",
                                   "mechanism": "m"}])
        assert "target-context match:" not in out
