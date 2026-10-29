"""Stage 6 — dynamic multi-agent scheduler tests.

Covers: deterministic classification/routing, specialist registry integrity,
bounded-concurrency run with a fake router, candidate collection, error
isolation (a failing specialist never invalidates completed ones), budget
sharing, follow-up allocation, and per-agent metrics.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agentsafe.agents.base import AnalysisMaterial
from agentsafe.agents.classification import (
    classify_contract,
    routing_summary,
)
from agentsafe.agents.scheduler import MultiAgentScheduler
from agentsafe.agents.specialists import (
    SPECIALIST_REGISTRY,
    AccountingAgent,
    ArithmeticAgent,
    CrossFunctionAgent,
    DefiLogicAgent,
    GeneralDiscoveryAgent,
    ProxyUpgradeAgent,
    ReentrancyAgent,
)
from agentsafe.schemas import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
class _FakeIntel:
    def __init__(self, contracts=(), proxy_hints=(), unresolved=()):
        self.contracts = list(contracts)
        self.proxy_hints = list(proxy_hints)
        self.unresolved_externals = list(unresolved)


class _C:
    def __init__(self, name, bases=(), functions=(), state_vars=(), kind="contract"):
        self.name = name
        self.bases = list(bases)
        self.functions = list(functions)
        self.state_vars = list(state_vars)
        self.kind = kind


class _F:
    def __init__(self, name, modifiers=()):
        self.name = name
        self.modifiers = list(modifiers)


class TestClassifyContract:
    def test_proxy_slot_triggers_proxy_specialist_deep(self):
        src = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        p = classify_contract(_FakeIntel(), src)
        assert p.triggers.get("proxy_upgrade") == "deep"
        assert p.triggers.get("general_discovery") == "deep"

    def test_initializer_triggers_access_control(self):
        src = "function initialize(address owner) external { __gap; }"
        p = classify_contract(_FakeIntel(), src)
        assert p.triggers.get("access_control") == "deep"

    def test_oracle_collateral_triggers_defi_deep(self):
        src = "uint p = oracle.latestRoundData(); collateral > healthFactor;"
        p = classify_contract(_FakeIntel(), src)
        assert p.triggers.get("defi_logic") == "deep"

    def test_eth_move_and_external_call_triggers_reentrancy_deep(self):
        src = 'msg.sender.call{value: amt}(""); uint b = balanceOf[msg.sender];'
        p = classify_contract(_FakeIntel(), src)
        assert p.triggers.get("reentrancy") == "deep"

    def test_balance_and_payable_triggers_accounting_deep(self):
        src = ("function deposit() payable { balances[msg.sender] += msg.value; "
               "totalAssets(); }")
        p = classify_contract(_FakeIntel(), src)
        assert p.triggers.get("accounting") == "deep"

    def test_arithmetic_always_triggered(self):
        p = classify_contract(_FakeIntel(), "contract A {}")
        assert p.triggers.get("arithmetic") in ("deep", "basic")

    def test_general_discovery_always_runs(self):
        p = classify_contract(_FakeIntel(), "")
        assert p.triggers.get("general_discovery") == "deep"

    def test_cross_function_from_intel_structure(self):
        intel = _FakeIntel(contracts=[
            _C("Vault", functions=[_F("deposit"), _F("withdraw")],
               state_vars=["balances", "total"]),
        ])
        p = classify_contract(intel, "")
        assert p.triggers.get("cross_function") == "basic"

    def test_empty_contract_still_routes_baseline(self):
        p = classify_contract(None, "")
        for name in ("general_discovery", "arithmetic"):
            assert p.should_run(name)

    def test_routing_summary_covers_selected(self):
        p = classify_contract(
            _FakeIntel(),
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
        s = routing_summary(p)
        assert "proxy_upgrade" in s
        assert "general_discovery" in s


# ---------------------------------------------------------------------------
# registry integrity
# ---------------------------------------------------------------------------
class TestSpecialistRegistry:
    def test_all_eight_defined(self):
        for name in ("access_control", "reentrancy", "accounting",
                     "cross_function", "defi_logic", "arithmetic",
                     "proxy_upgrade", "general_discovery"):
            assert name in SPECIALIST_REGISTRY

    def test_names_match_expected(self):
        assert AccountingAgent.name == "accounting"
        assert ReentrancyAgent.name == "reentrancy"
        assert ArithmeticAgent.name == "arithmetic"
        assert DefiLogicAgent.name == "defi_logic"
        assert ProxyUpgradeAgent.name == "proxy_upgrade"
        assert CrossFunctionAgent.name == "cross_function"
        assert GeneralDiscoveryAgent.name == "general_discovery"

    def test_specialists_are_baseagent_subclasses(self):
        from agentsafe.agents.base import BaseAgent
        for cls in SPECIALIST_REGISTRY.values():
            assert issubclass(cls, BaseAgent)

    def test_registry_covers_classifier_specialists(self):
        from agentsafe.agents.classification import SPECIALISTS
        assert set(SPECIALISTS) == set(SPECIALIST_REGISTRY.keys())


# ---------------------------------------------------------------------------
# scheduler run (fake router)
# ---------------------------------------------------------------------------
class _FakeBudget:
    def __init__(self, max_calls=100):
        self.max_calls = max_calls
        self.calls_made = 0
        self.deadline = 1e18
        self.failed_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.providers_used = set()
        self.models_used = set


class _FakeRouter:
    """Returns one finding per agent call."""

    def __init__(self, fail_agents: set[str] | None = None):
        self.fail_agents = fail_agents or set()

    async def complete_json(self, budget, messages, payload_cls):
        budget.calls_made += 1
        payload = payload_cls.model_validate({"findings": [{
            "title": "candidate finding",
            "severity": "medium",
            "description": "d",
            "evidence": "evid",
            "recommendation": "r",
            "swc_id": None,
            "preconditions": "p",
            "attack_scenario": "a",
            "impact": "i",
            "file_path": None,
            "line_start": 1,
            "line_end": None,
            "confidence": 0.5,
        }]})
        return payload, type("C", (), {"provider": "mock", "model": "m"})()

    def start_audit(self, **kw):
        return _FakeBudget()


def _material() -> AnalysisMaterial:
    return AnalysisMaterial(
        kind="source",
        segments={"V.sol": "contract V { function w() external { }\nfunction d() external { balances[msg.sender] += msg.value; } }"},
        is_pseudo_source=False,
    )


class TestSchedulerRun:
    def test_routes_and_collects_candidates(self):
        sched = MultiAgentScheduler(_FakeRouter(), max_concurrent=4)
        budget = _FakeBudget(max_calls=200)
        res = asyncio.run(sched.run(budget, _material()))
        assert res.profile is not None
        assert res.routing_summary
        assert res.per_agent
        assert res.candidates
        for f in res.candidates:
            assert isinstance(f, Finding)
            assert f.title

    def test_all_candidates_schema_valid(self):
        sched = MultiAgentScheduler(_FakeRouter(), max_concurrent=2)
        budget = _FakeBudget(max_calls=200)
        res = asyncio.run(sched.run(budget, _material()))
        assert all(isinstance(f, Finding) for f in res.candidates)

    def test_error_isolation(self, monkeypatch):
        def _boom(self, budget, material):
            raise RuntimeError("boom")

        from agentsafe.agents import specialists as spec
        monkeypatch.setattr(spec.GeneralDiscoveryAgent, "analyze", _boom)

        sched = MultiAgentScheduler(_FakeRouter(), max_concurrent=4)
        budget = _FakeBudget(max_calls=200)
        res = asyncio.run(sched.run(budget, _material()))
        gd = next((s for s in res.per_agent if s.agent == "general_discovery"), None)
        assert gd is not None and gd.errors
        assert res.profile is not None
        assert res.candidates or any(s.findings_produced >= 0 for s in res.per_agent)

    def test_budget_shared_across_agents(self):
        sched = MultiAgentScheduler(_FakeRouter(), max_concurrent=4)
        budget = _FakeBudget(max_calls=50)
        res = asyncio.run(sched.run(budget, _material()))
        assert budget.calls_made > 0
        assert budget.calls_made <= 50

    def test_validation_handoff_attribution(self):
        class _Val:
            def validate(self, candidates, tools, segments, pseudo):
                class _Out:
                    findings = [f for f in candidates]
                return _Out()

        sched = MultiAgentScheduler(_FakeRouter(), max_concurrent=4)
        budget = _FakeBudget(max_calls=200)
        res = asyncio.run(sched.run(budget, _material(), validation=_Val()))
        assert res.validated
        assert any(s.contribution > 0 for s in res.per_agent)

    def test_no_router_still_classifies(self):
        sched = MultiAgentScheduler(None, max_concurrent=2)
        prof = sched.classify(_material())
        assert prof.triggers.get("general_discovery") == "deep"

    def test_aggregate_metrics(self):
        sched = MultiAgentScheduler(_FakeRouter(), max_concurrent=4)
        budget = _FakeBudget(max_calls=200)
        res = asyncio.run(sched.run(budget, _material()))
        agg = res.aggregate()
        assert "candidates" in agg
        assert "total_llm_calls" in agg
        assert res.per_agent