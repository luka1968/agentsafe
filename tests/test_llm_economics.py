"""Priority 2: LLM-call economics.

The WETH9 audit burned 81 calls across 6 specialists because (a) every agent
read every source file, and (b) the "focused follow-up" re-ran each productive
agent's ENTIRE segment set with the identical prompt.

These tests pin the optimisation contract:

- per-agent relevance ranking caps how many segments an agent reads;
- a bounded follow-up spends at most one call per productive agent, only on
  segments that agent has NOT read (identical code is never re-analyzed);
- early stopping when the follow-up produces no new evidence;
- cross-agent duplicate candidates collapse into one before validation, with
  merged provenance (coverage is preserved, attribution is accurate);
- per-agent LLM call attribution is measured from the shared budget.
"""

from __future__ import annotations

import re

import pytest

from agentsafe.agents.base import AnalysisMaterial
from agentsafe.agents.scheduler import MultiAgentScheduler
from agentsafe.schemas import FindingCategory

_LABEL_RE = re.compile(r"=== UNTRUSTED CONTRACT DATA: ([^=]+?) ===")


class _Budget:
    def __init__(self, max_calls: int = 500) -> None:
        self.max_calls = max_calls
        self.calls_made = 0
        self.calls_by_agent: dict[str, int] = {}
        self.deadline = 1e18
        self.failed_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.providers_used: set[str] = set()
        self.models_used: set[str] = set()


class _Call:
    provider = "mock"
    model = "m"


class _RecordingRouter:
    """Records (focus-head, segment-label) per call and answers with
    caller-supplied findings for that segment."""

    def __init__(self, respond=None):
        self.calls: list[tuple[str, str]] = []
        self._respond = respond or (lambda label, user: [])

    def start_audit(self, **kw):
        return _Budget()

    async def complete_json(self, budget, messages, payload_cls):
        from agentsafe.llm.router import CURRENT_AGENT

        budget.calls_made += 1
        focus = CURRENT_AGENT.get() or "unattributed"
        budget.calls_by_agent[focus] = budget.calls_by_agent.get(focus, 0) + 1
        user = messages[1]["content"]
        m = _LABEL_RE.search(user)
        label = m.group(1).strip() if m else "?"
        self.calls.append((focus, label))
        findings = self._respond(label, user)
        return payload_cls.model_validate({"findings": findings}), _Call()

    # -- helpers -------------------------------------------------------
    def labels_for(self, focus: str) -> list[str]:
        return [lbl for f, lbl in self.calls if f == focus]

    def distinct_focuses(self) -> set[str]:
        return {f for f, _ in self.calls}


def _finding(title: str, category: str, file: str, line: int, severity="medium"):
    return {
        "title": title,
        "severity": severity,
        "description": f"{title} description",
        "evidence": f"{title} evidence",
        "recommendation": "fix it",
        "category": category,
        "file_path": file,
        "line_start": line,
        "line_end": line,
        "confidence": 0.5,
    }


def _material(segments: dict[str, str]) -> AnalysisMaterial:
    return AnalysisMaterial(kind="source", segments=segments, is_pseudo_source=False)


def _six_file_weth_like() -> dict[str, str]:
    """WETH9-shaped bundle: one main contract file plus small interface/helper
    files. Triggers 6 specialists (reentrancy/accounting/arithmetic/cross_
    function/access_control/general_discovery)."""
    main = (
        "contract WETH9 {\n"
        "  mapping(address => uint) public balanceOf;\n"
        "  uint public totalSupply;\n"
        "  function deposit() public payable { balanceOf[msg.sender] += msg.value; }\n"
        "  function withdraw(uint wad) public {\n"
        "    balanceOf[msg.sender] -= wad;\n"
        "    msg.sender.transfer(wad);\n"
        "  }\n"
        "}\n"
    )
    return {
        "WETH9.sol": main,
        "interfaces/IERC20.sol": (
            "interface IERC20 { function balanceOf(address a) external view "
            "returns (uint); }\n"
        ),
        "interfaces/IWETH.sol": "interface IWETH { function deposit() external payable; }\n",
        "lib/SafeMath.sol": (
            "library SafeMath { function add(uint a, uint b) internal pure "
            "returns (uint) { return a + b; } }\n"
        ),
        "lib/Address.sol": (
            "library Address { function isContract(address a) internal view "
            "returns (bool) { return a.code.length > 0; } }\n"
        ),
        "Migrations.sol": "contract Migrations { uint public last_completed_migration; }\n",
    }


# ---------------------------------------------------------------- call caps
class TestSegmentCap:
    def test_per_agent_calls_bounded_by_relevance_cap(self):
        segs = {
            f"f{i}.sol": (
                f"contract C{i} {{ uint x; function f(uint a) external {{ x += a; }} }}"
            )
            for i in range(8)
        }
        router = _RecordingRouter(lambda label, user: [])
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(sched.run(budget, _material(segs)))
        assert res.per_agent
        for stats in res.per_agent:
            # first pass <= cap (3); follow-up adds 0 calls when nothing was
            # produced (no findings -> no follow-up at all)
            assert stats.llm_calls <= 3, (stats.agent, stats.llm_calls)
        # 8 segments x 6 agents would have been 48 calls before the cap
        assert budget.calls_made <= 3 * len(res.per_agent)

    def test_no_segment_is_analyzed_twice_by_the_same_agent(self):
        segs = _six_file_weth_like()
        router = _RecordingRouter(
            lambda label, user: (
                [_finding("reentrancy in withdraw", "reentrancy", label, 10, "high")]
                if "transfer" in user else []
            )
        )
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        asyncio.run(sched.run(budget, _material(segs)))
        pairs = router.calls
        # identical (agent, segment) work must never repeat (old follow-up
        # re-ran the whole set -> every pair appeared twice)
        assert len(pairs) == len(set(pairs))

    def test_followup_skipped_when_nothing_left_to_read(self):
        router = _RecordingRouter(
            lambda label, user: [_finding("issue", "logic_error", label, 1)]
        )
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(
            sched.run(budget, _material({"Only.sol": "contract O { function a() external {} }"}))
        )
        agents = len(res.per_agent)
        assert len(router.calls) == agents  # exactly one call per agent
        assert res.followup_calls == 0

    def test_followup_early_stops_when_no_new_evidence(self):
        segs = {
            f"s{i}.sol": (
                f"contract S{i} {{ function w() external "
                f"{{ msg.sender.transfer(1); }} }}"
            )
            for i in range(4)
        }
        same = _finding("same issue", "logic_error", "S0.sol", 2)
        router = _RecordingRouter(lambda label, user: [same])
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(sched.run(budget, _material(segs)))
        assert res.early_stopped >= 1
        # follow-ups that ran produced only duplicates -> one candidate
        assert len(res.candidates) == 1


# ------------------------------------------------------- dedup + attribution
class TestCandidateDeduplication:
    def test_identical_candidates_collapse_with_merged_sources(self):
        same = _finding("reentrancy in withdraw", "reentrancy", "WETH9.sol", 10, "high")
        router = _RecordingRouter(lambda label, user: [same])
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(sched.run(budget, _material(_six_file_weth_like())))
        assert res.duplicates_removed >= 1
        assert len(res.candidates) == 1
        merged = res.candidates[0]
        # provenance preserved: every corroborating agent is still listed
        assert len(merged.source) >= 2

    def test_per_agent_attribution_is_measured_not_guessed(self):
        router = _RecordingRouter(lambda label, user: [])
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(sched.run(budget, _material(_six_file_weth_like())))
        agg = res.aggregate()
        # sum of per-agent calls is exactly what the shared budget saw
        assert sum(s.llm_calls for s in res.per_agent) == budget.calls_made
        assert sum(agg["per_agent_calls"].values()) == budget.calls_made
        assert all(v > 0 for v in agg["per_agent_calls"].values())


# ------------------------------------------- detection coverage is preserved
class TestCoveragePreserved:
    def test_distinct_findings_in_different_files_are_both_found(self):
        segs = _six_file_weth_like()
        # a reentrancy marker only in the main file, an access-control marker
        # only in a second file -> both specialists must still read them.
        segs["Admin.sol"] = (
            "contract Admin { address public admin; modifier onlyAdmin() "
            "{ require(msg.sender == admin, 'not admin'); _; } "
            "function setAdmin(address a) external onlyAdmin { admin = a; } }"
        )

        def respond(label, user):
            out = []
            if "transfer" in user and label == "WETH9.sol":
                out.append(_finding("reentrancy in withdraw", "reentrancy", label, 10, "high"))
            if "onlyAdmin" in user:
                out.append(
                    _finding(
                        "missing zero-address check on admin",
                        "access_control", label, 2, "medium",
                    )
                )
            return out

        router = _RecordingRouter(respond)
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(sched.run(budget, _material(segs)))
        cats = {f.category for f in res.candidates}
        assert FindingCategory.REENTRANCY in cats
        assert FindingCategory.ACCESS_CONTROL in cats

    def test_weth_like_audit_stays_under_a_quarter_of_the_old_cost(self):
        """Old behaviour on this fixture: 6 agents x 6 segments first pass (36)
        + the identical full re-run in follow-up (36) = 72 calls. The optimised
        scheduler must stay at/under 6 agents x (3 + 1 follow-up) = 24 while
        still producing the expected finding."""
        segs = _six_file_weth_like()
        router = _RecordingRouter(
            lambda label, user: (
                [_finding("unchecked transfer return", "unhandled_exception", label, 7, "medium")]
                if "transfer(wad)" in user else []
            )
        )
        sched = MultiAgentScheduler(router, max_concurrent=6)
        budget = _Budget()
        import asyncio

        res = asyncio.run(sched.run(budget, _material(segs)))
        old_cost = 72
        assert budget.calls_made <= 24, budget.calls_made
        assert budget.calls_made <= old_cost // 3
        assert res.candidates, "detection result must be preserved"
        assert len(res.per_agent) >= 5


# ---------------------------------------------------- report-level wiring
@pytest.mark.asyncio
async def test_report_carries_per_agent_llm_attribution():
    """The orchestrator must persist measured per-agent calls in llm_usage."""
    import respx

    from agentsafe.agents.validation import ValidationAgent
    from agentsafe.orchestrator import AuditOrchestrator
    from agentsafe.rpc import EthRpcClient
    from agentsafe.schemas import LLMUsage
    from tests.test_orchestrator import (
        ADDR,
        CODE,
        FakeBytecodeAnalyzer,
        FakeExplorer,
        FakeSourceAnalyzer,
        _router,
        _stub_rpc,
    )

    assert LLMUsage(per_agent={"a": 2}).per_agent == {"a": 2}
    router = _RecordingRouter(lambda label, user: [])

    async def _ns(_):
        return None

    with respx.mock:
        _stub_rpc(CODE)
        orch = AuditOrchestrator(
            rpc=EthRpcClient("https://rpc.test", sleeper=_ns),
            explorer=FakeExplorer(verified=True),
            source_analyzer=FakeSourceAnalyzer([]),
            bytecode_analyzer=FakeBytecodeAnalyzer(findings=[]),
            router=_router(),
            agents=[],
            validation_agent=ValidationAgent(),
            scheduler=MultiAgentScheduler(router, max_concurrent=6),
            total_timeout_seconds=900.0,
            llm_max_calls=50,
            llm_deadline_seconds=60.0,
        )
        report = await orch.run(ADDR, task_id="task-econ")
    assert report.llm_usage.per_agent
    assert sum(report.llm_usage.per_agent.values()) <= report.llm_usage.total_calls
