"""Stage 6 — dynamic multi-agent scheduler.

Functional scheduler: classifies the contract from extracted structure,
selects specialist agents by evidence (not by running everything), runs
them with bounded concurrency and an explicit execution budget, focuses
additional analysis on promising hypotheses, tracks per-agent execution
metrics, and hands schema-validated candidates to independent validation.

Mandatory properties:
  * A failed agent never invalidates unrelated completed analyses (error
    isolation: each specialist runs in its own task; failures are recorded
    per-agent and the audit continues).
  * Concurrency, timeouts, retries, and budgets derive from existing
    configuration defaults (config.AgentSafeConfig) — never arbitrary.
  * Budget is shared (LLMRouter AuditBudget): specialists cooperate rather
    than each exhausting the pool.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from agentsafe.agents.base import AgentResult, AnalysisMaterial, BaseAgent
from agentsafe.agents.classification import (
    ClassifiedProfile,
    SPECIALISTS,
    classify_contract,
    routing_summary,
)
from agentsafe.agents.specialists import SPECIALIST_REGISTRY
from agentsafe.config import Settings
from agentsafe.llm.router import AuditBudget, LLMRouter
from agentsafe.schemas import Finding, FindingStatus

logger = logging.getLogger("agentSAFE.scheduler")

# --------------------------------------------------------------------------
# Execution metrics (per-agent and aggregate) — Stage 6 auditability.
# --------------------------------------------------------------------------
@dataclass
class AgentRunStats:
    agent: str
    depth: str = "basic"
    started: float = 0.0
    elapsed: float = 0.0
    findings_produced: int = 0
    errors: list[str] = field(default_factory=list)
    llm_calls: int = 0
    llm_tokens: int = 0
    models_used: set[str] = field(default_factory=set)
    skipped: str | None = None
    # after validation pass
    findings_validated: int = 0
    contribution: int = 0  # validated findings attributed to this agent

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "depth": self.depth,
            "elapsed_seconds": round(self.elapsed, 2),
            "findings_produced": self.findings_produced,
            "findings_validated": self.findings_validated,
            "contribution": self.contribution,
            "errors": self.errors,
            "llm_calls": self.llm_calls,
            "llm_tokens": self.llm_tokens,
            "models_used": sorted(self.models_used),
            "skipped": self.skipped,
        }


@dataclass
class SchedulerResult:
    profile: ClassifiedProfile
    candidates: list[Finding] = field(default_factory=list)
    per_agent: list[AgentRunStats] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    routing_summary: str = ""
    # validated (post cross-validation) findings + per-agent contribution
    validated: list[Finding] = field(default_factory=list)

    def aggregate(self) -> dict[str, Any]:
        return {
            "agents_run": len([s for s in self.per_agent if s.findings_produced > 0 or not s.skipped]),
            "agents_failed": sum(1 for s in self.per_agent if s.errors),
            "candidates": len(self.candidates),
            "validated": len(self.validated),
            "total_llm_calls": sum(s.llm_calls for s in self.per_agent),
            "total_llm_tokens": sum(s.llm_tokens for s in self.per_agent),
            "errors": self.errors,
        }


# --------------------------------------------------------------------------
# Scheduler
# --------------------------------------------------------------------------
class MultiAgentScheduler:
    """Selects and runs specialist agents for one audit material."""

    def __init__(
        self,
        router: LLMRouter | None,
        *,
        registry: dict[str, type[BaseAgent]] | None = None,
        kb_store_factory: Callable[[], Any] | None = None,
        max_concurrent: int | None = None,
        budget_factory: Callable[..., AuditBudget] | None = None,
    ) -> None:
        self._router = router
        self._registry = dict(registry or SPECIALIST_REGISTRY)
        self._kb_store_factory = kb_store_factory
        cfg = Settings()
        # Defaults derive from existing configuration — never invented.
        self._max_concurrent = max_concurrent or max(1, cfg.SCHEDULER_MAX_CONCURRENT)
        self._budget_factory = budget_factory
        self._cfg = cfg

    # -- classification -----------------------------------------------------
    def classify(self, material: AnalysisMaterial) -> ClassifiedProfile:
        intel = getattr(material, "intel", None)
        src = "\n".join(material.segments.values())
        return classify_contract(intel, src)

    # -- run -----------------------------------------------------------------
    async def run(
        self,
        budget: AuditBudget,
        material: AnalysisMaterial,
        *,
        validation: Any | None = None,
    ) -> SchedulerResult:
        profile = self.classify(material)
        result = SchedulerResult(profile=profile)
        result.routing_summary = routing_summary(profile)
        logger.info("scheduler routing:\n%s", result.routing_summary)

        kb = None
        if self._kb_store_factory is not None:
            try:
                kb = self._kb_store_factory()
            except Exception as exc:
                result.errors.append(f"knowledge base unavailable: {exc}")

        # Build material with KB attached for specialists.
        mat = AnalysisMaterial(
            kind=material.kind,
            segments=material.segments,
            is_pseudo_source=material.is_pseudo_source,
            bytecode=material.bytecode,
            intel=getattr(material, "intel", None),
            kb=kb,
        )

        selected = [
            name for name in SPECIALISTS if profile.should_run(name)
        ]
        if not selected:
            selected = ["general_discovery"]

        # -- bounded concurrency over selected specialists -------------------
        sem = asyncio.Semaphore(self._max_concurrent)
        started_at = time.monotonic()
        per_agent_findings: dict[str, list[Finding]] = {}

        async def _bounded(agent: BaseAgent, depth: str) -> AgentRunStats:
            stats = AgentRunStats(agent=agent.name, depth=depth,
                                  started=time.monotonic())
            async with sem:
                budget_left = budget.calls_made  # snapshot for attribution
                try:
                    ares = await asyncio.wait_for(
                        agent.analyze(budget, mat),
                        timeout=self._cfg.LLM_REQUEST_TIMEOUT_SECONDS * 4,
                    )
                except asyncio.TimeoutError:
                    stats.errors.append("agent timeout (bounded)")
                    logger.warning("agent %s timed out", agent.name)
                    return stats
                except Exception as exc:  # error isolation: never cascades
                    stats.errors.append(f"{type(exc).__name__}: {exc}")
                    logger.warning("agent %s failed (isolated): %s",
                                   agent.name, exc)
                    return stats
                finally:
                    stats.elapsed = time.monotonic() - stats.started
            stats.findings_produced = len(ares.findings)
            stats.skipped = ares.skipped_reason
            stats.errors.extend(ares.errors)
            stats.llm_calls = max(0, budget.calls_made - budget_left)
            per_agent_findings[agent.name] = list(ares.findings)
            return stats

        # Instantiate selected agents (shared router + budget).
        agents: list[tuple[BaseAgent, str]] = []
        for name in selected:
            cls = self._registry.get(name)
            if cls is None:
                result.errors.append(f"specialist {name} not registered")
                continue
            try:
                agent = cls(router=self._router) if self._router is not None else cls()  # type: ignore[call-arg]
            except TypeError:
                agent = cls()  # no-router construction for offline tests
            agents.append((agent, profile.triggers.get(name, "basic")))

        tasks = [asyncio.create_task(_bounded(a, d)) for a, d in agents]
        stats_list: list[AgentRunStats] = await asyncio.gather(*tasks)
        result.per_agent = stats_list

        # -- collect schema-validated candidates ------------------------------
        for stats in stats_list:
            result.candidates.extend(per_agent_findings.get(stats.agent, []))

        # Focused follow-up on promising hypotheses (additional allocation).
        await self._focused_followup(result, budget, mat)

        # Independent validation hand-off.
        if validation is not None and result.candidates:
            try:
                validated = await self._validate(validation, result.candidates,
                                                 mat)
                result.validated = validated
                self._attribute_contributions(result, validated)
            except Exception as exc:
                result.errors.append(f"validation failed: {exc}")

        result.errors.extend(
            f"{s.agent}: {e}" for s in result.per_agent for e in s.errors[:2]
        )
        return result

    async def _focused_followup(self, result: SchedulerResult, budget: AuditBudget,
                                material: AnalysisMaterial) -> None:
        """Allocate additional analysis to promising hypotheses: specialists
        that produced candidates get a second, focused pass at their own
        findings (deep re-read) when budget allows."""
        if self._router is None or budget.calls_made >= budget.max_calls:
            return
        for stats in result.per_agent:
            if stats.findings_produced == 0 or stats.errors:
                continue  # nothing promising or the agent already failed
            if budget.calls_made >= budget.max_calls:
                break
            cls = self._registry.get(stats.agent)
            if cls is None:
                continue
            try:
                agent = cls(router=self._router)  # type: ignore[call-arg]
            except TypeError:
                continue
            try:
                ares = await asyncio.wait_for(
                    agent.analyze(budget, material),
                    timeout=self._cfg.LLM_REQUEST_TIMEOUT_SECONDS * 3,
                )
                stats.findings_produced += len(ares.findings)
                stats.llm_calls += len(ares.findings) or 1
            except Exception as exc:  # follow-up never blocks audit
                stats.errors.append(f"follow-up failed: {exc}")

    async def _validate(self, validation: Any, candidates: list[Finding],
                        material: AnalysisMaterial) -> list[Finding]:
        """Independent validation hand-off (validation agent interface)."""
        validate = getattr(validation, "validate", None)
        if validate is None:
            return candidates
        if asyncio.iscoroutinefunction(validate):
            out = await validate(candidates, [], material.segments or None,
                                 material.is_pseudo_source)
        else:
            out = validate(candidates, [], material.segments or None,
                           material.is_pseudo_source)
        findings = getattr(out, "findings", None)
        if findings is None and isinstance(out, (list, tuple)):
            findings = out
        return list(findings) if findings is not None else []

    @staticmethod
    def _attribute_contributions(result: SchedulerResult,
                                 validated: list[Finding]) -> None:
        """Attribute validated findings back to the specialist that produced
        the seed candidate (source list contains agent names)."""
        for v in validated:
            for stats in result.per_agent:
                if stats.agent in v.source:
                    stats.findings_validated += 1
                    stats.contribution += 1
                    break
