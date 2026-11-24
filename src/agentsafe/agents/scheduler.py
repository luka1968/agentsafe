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
import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
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
    # Honest scope bookkeeping surfaced into report limitations.
    notes: list[str] = field(default_factory=list)
    # Segment labels this agent actually analyzed (for source-coverage
    # accounting: which agent read which segment).
    analyzed_labels: list[str] = field(default_factory=list)
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
            "notes": self.notes,
            "analyzed_labels": list(self.analyzed_labels),
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
    # LLM-economics bookkeeping (accurate, measured - never estimated):
    duplicates_removed: int = 0     # cross-agent duplicate candidates collapsed
    followup_calls: int = 0         # extra calls spent on bounded follow-up
    early_stopped: int = 0          # follow-ups that produced NO new evidence
    notes: list[str] = field(default_factory=list)

    def aggregate(self) -> dict[str, Any]:
        return {
            "agents_run": len([s for s in self.per_agent if s.findings_produced > 0 or not s.skipped]),
            "agents_failed": sum(1 for s in self.per_agent if s.errors),
            "candidates": len(self.candidates),
            "validated": len(self.validated),
            "total_llm_calls": sum(s.llm_calls for s in self.per_agent),
            "total_llm_tokens": sum(s.llm_tokens for s in self.per_agent),
            "duplicates_removed": self.duplicates_removed,
            "followup_calls": self.followup_calls,
            "early_stopped": self.early_stopped,
            "per_agent_calls": {
                s.agent: s.llm_calls for s in self.per_agent if s.llm_calls
            },
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
        labels_by_agent: dict[str, list[str]] = {}

        async def _bounded(agent: BaseAgent, depth: str) -> AgentRunStats:
            stats = AgentRunStats(agent=agent.name, depth=depth,
                                  started=time.monotonic())
            async with sem:
                try:
                    ares = await asyncio.wait_for(
                        agent.analyze(budget, mat),
                        timeout=self._cfg.LLM_REQUEST_TIMEOUT_SECONDS * 4,
                    )
                except asyncio.TimeoutError:
                    stats.errors.append("agent timeout (bounded)")
                    logger.warning("agent %s timed out", agent.name)
                    stats.llm_calls = self._calls_spent(budget, agent.name)
                    return stats
                except Exception as exc:  # error isolation: never cascades
                    stats.errors.append(f"{type(exc).__name__}: {exc}")
                    logger.warning("agent %s failed (isolated): %s",
                                   agent.name, exc)
                    stats.llm_calls = self._calls_spent(budget, agent.name)
                    return stats
                finally:
                    stats.elapsed = time.monotonic() - stats.started
            stats.findings_produced = len(ares.findings)
            stats.skipped = ares.skipped_reason
            stats.errors.extend(ares.errors)
            stats.notes = list(ares.notes)
            stats.analyzed_labels = list(ares.analyzed_labels)
            # Measured attribution (task-local context var, concurrency-safe):
            # a calls_made delta around an await would count other agents.
            stats.llm_calls = self._calls_spent(budget, agent.name)
            per_agent_findings[agent.name] = list(ares.findings)
            labels_by_agent[agent.name] = list(ares.analyzed_labels)
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
        for stats in stats_list:
            result.notes.extend(stats.notes)

        # Deduplicate BEFORE any further work: the same root cause reported by
        # several specialists is one candidate (sources merged, strongest
        # evidence kept) - never N LLM-validated duplicates.
        result.candidates, removed = self._dedupe_candidates(result.candidates)
        result.duplicates_removed += removed

        # Focused follow-up on promising hypotheses: bounded to ONE extra call
        # per productive agent, only on code the agent has NOT read yet.
        await self._focused_followup(
            result, budget, mat, per_agent_findings, labels_by_agent)

        # Follow-up can introduce cross-agent duplicates too: collapse again.
        if result.candidates:
            result.candidates, removed2 = self._dedupe_candidates(result.candidates)
            result.duplicates_removed += removed2

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

    # ---------------------------------------------------------------- dedup
    _SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    @staticmethod
    def _norm_title(title: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", (title or "").lower()).strip()

    @classmethod
    def _same_root_cause(cls, a: Finding, b: Finding) -> bool:
        """Deterministic cross-agent duplicate test (same root cause, not just
        a shared category): same file + nearby line + same category, or a
        near-identical title inside the same category."""
        cat_a = a.category.value if a.category else ""
        cat_b = b.category.value if b.category else ""
        if cat_a != cat_b:
            return False
        file_a = (a.file_path or "").lower()
        file_b = (b.file_path or "").lower()
        both_located = bool(file_a and file_b)
        if both_located:
            if file_a != file_b:
                return False
            if a.line_start and b.line_start:
                if abs(a.line_start - b.line_start) <= 5:
                    return True
        ta, tb = cls._norm_title(a.title), cls._norm_title(b.title)
        if not ta or not tb:
            return False
        return SequenceMatcher(None, ta, tb).ratio() >= 0.85

    @classmethod
    def _dedupe_candidates(
        cls, candidates: Sequence[Finding]
    ) -> tuple[list[Finding], int]:
        """Collapse candidates describing the same root cause.

        Survivor keeps the strongest severity and the richest evidence, and
        accumulates every contributing agent in ``source`` so per-agent
        attribution stays complete.
        """
        kept: list[Finding] = []
        removed = 0
        for f in candidates:
            host = next((k for k in kept if cls._same_root_cause(k, f)), None)
            if host is None:
                kept.append(f)
                continue
            removed += 1
            host.source = list(dict.fromkeys([*(host.source or []), *(f.source or [])]))
            if cls._SEV_RANK.get(f.severity.value, 0) > cls._SEV_RANK.get(
                host.severity.value, 0
            ):
                host.severity = f.severity
            for attr in ("evidence", "preconditions", "attack_scenario", "impact",
                         "recommendation"):
                cur = getattr(host, attr) or ""
                incoming = getattr(f, attr) or ""
                if len(incoming) > len(cur):
                    setattr(host, attr, incoming)
            if host.confidence is not None or f.confidence is not None:
                host.confidence = max(
                    x for x in (host.confidence, f.confidence) if x is not None
                )
            host.knowledge_references = list(
                dict.fromkeys(
                    [*(host.knowledge_references or []), *(f.knowledge_references or [])]
                )
            )
        return kept, removed

    @staticmethod
    def _calls_spent(budget: AuditBudget, agent: str) -> int:
        """Calls charged to this agent so far (measured at record time)."""
        return int(getattr(budget, "calls_by_agent", {}).get(agent, 0))

    async def _focused_followup(self, result: SchedulerResult, budget: AuditBudget,
                                material: AnalysisMaterial,
                                first_pass: dict[str, list[Finding]],
                                analyzed: dict[str, list[str]]) -> None:
        """Bounded follow-up: at most ONE extra call per productive agent, on
        the highest-evidence segment that agent has NOT read yet.

        - No unanalyzed relevant segment -> no call at all (identical code is
          never analyzed twice);
        - the agent's existing findings are listed in the prompt so only NEW,
          distinct issues are requested;
        - if the follow-up yields no new evidence, analysis stops there
          (early stopping) instead of looping;
        - calls are attributed from the budget delta (measured, not guessed).
        """
        if self._router is None:
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
            prior = first_pass.get(stats.agent, [])
            before = self._calls_spent(budget, stats.agent)
            try:
                ares = await asyncio.wait_for(
                    agent.followup(
                        budget, material, prior, analyzed.get(stats.agent, [])
                    ),
                    timeout=self._cfg.LLM_REQUEST_TIMEOUT_SECONDS * 3,
                )
            except Exception as exc:  # follow-up never blocks audit
                stats.llm_calls = self._calls_spent(budget, stats.agent)
                result.followup_calls += max(0, stats.llm_calls - before)
                stats.errors.append(f"follow-up failed: {exc}")
                continue
            spent = max(0, self._calls_spent(budget, stats.agent) - before)
            stats.llm_calls = self._calls_spent(budget, stats.agent)
            result.followup_calls += spent
            if ares.skipped_reason:
                continue  # nothing left to read: zero calls spent
            if ares.errors:
                stats.errors.extend(ares.errors[:1])
                continue
            stats.analyzed_labels.extend(ares.analyzed_labels)
            known = [*result.candidates, *prior]
            new = [
                f for f in ares.findings
                if not any(self._same_root_cause(k, f) for k in known)
            ]
            if not new:
                result.early_stopped += 1
                logger.info(
                    "follow-up for %s produced no new evidence (early stop)",
                    stats.agent,
                )
                continue
            stats.findings_produced += len(new)
            first_pass.setdefault(stats.agent, []).extend(new)
            result.candidates.extend(new)

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
        """Attribute validated findings to the specialist that FIRST produced
        the seed candidate (``source[0]``). Corroborating agents stay listed in
        ``source`` but are not double-counted as contributors."""
        for v in validated:
            primary = v.source[0] if v.source else None
            if not primary:
                continue
            for stats in result.per_agent:
                if stats.agent == primary:
                    stats.findings_validated += 1
                    stats.contribution += 1
                    break
