"""Agent framework: bounded LLM analysis with strict output schemas.

Contract code is treated as UNTRUSTED DATA. Agents never confirm findings:
everything they emit is llm_suggested and must pass the ValidationAgent.
Token/char budgets split large codebases into per-file/per-chunk calls, all
charged against the same per-audit LLM budget.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agentsafe.intel.render import render_intel_brief, render_kb_snippets
from agentsafe.llm.prompts import (
    BASIC_SCAN_SUFFIX,
    DEEP_DIVE_SUFFIX,
    system_prompt,
)
from agentsafe.llm.router import AuditBudget, LLMRouter
from agentsafe.schemas import Finding, FindingStatus

logger = logging.getLogger("agentSAFE.agents")

MAX_SEGMENT_CHARS = 8_000  # per LLM call, ~2k tokens of code (AgentLISA-style: smallest relevant sample)
MAX_TOTAL_ANALYZED_CHARS = 45_000  # per agent across whole audit (focused batches, not whole repo)


class LLMFindingPayload(BaseModel):
    """Strict wire format the LLM must produce for one finding."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=300)
    severity: str
    description: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    recommendation: str = ""
    swc_id: str | None = Field(default=None, max_length=16)
    cwe_id: str | None = Field(default=None, max_length=16)
    preconditions: str = ""
    attack_scenario: str = ""
    impact: str = ""
    file_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("severity")
    @classmethod
    def _severity(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError(f"invalid severity: {v!r}")
        return v

    @field_validator("line_end")
    @classmethod
    def _line_range(cls, v: int | None, info) -> int | None:
        start = info.data.get("line_start")
        if v is not None and start is not None and v < start:
            raise ValueError("line_end must be >= line_start")
        return v


class LLMFindingsPayload(BaseModel):
    """Root wire format: {"findings": [...]}."""

    model_config = ConfigDict(extra="forbid")
    findings: list[LLMFindingPayload] = Field(default_factory=list, max_length=50)


@dataclass
class AnalysisMaterial:
    """What the agents look at. Either verified source or bytecode-derived."""

    kind: str  # "source" | "bytecode"
    # For source: path -> content. For bytecode: label -> pseudo-source/disasm text.
    segments: dict[str, str]
    is_pseudo_source: bool = False
    bytecode: str | None = None
    # Deterministic contract intelligence (None when unavailable — agents then
    # fall back to raw-source analysis; never fabricated).
    intel: Any = None
    # Optional security knowledge base for mechanism retrieval (None disables).
    kb: Any = None

    def total_chars(self) -> int:
        return sum(len(v) for v in self.segments.values())

    def text(self) -> str:
        return "\n".join(self.segments.values())


@dataclass
class AgentResult:
    agent: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    segments_analyzed: int = 0
    skipped_reason: str | None = None


class BaseAgent:
    """One specialized LLM analyst. Subclasses set name/focus/keywords."""

    name: str = "base"
    focus: str = ""
    keywords: tuple[str, ...] = ()
    material_is_pseudo: bool = False

    max_segment_chars: int = MAX_SEGMENT_CHARS
    max_total_chars: int = MAX_TOTAL_ANALYZED_CHARS

    def __init__(self, router: LLMRouter) -> None:
        self._router = router

    def _chunk(self, path: str, content: str) -> list[tuple[str, str]]:
        """Split oversized files at line boundaries (never mid-line silently)."""
        if len(content) <= self.max_segment_chars:
            return [(path, content)]
        chunks: list[tuple[str, str]] = []
        lines = content.splitlines(keepends=True)
        current: list[str] = []
        size = 0
        part = 0
        for line in lines:
            if size + len(line) > self.max_segment_chars and current:
                part += 1
                chunks.append((f"{path}#part{part}", "".join(current)))
                current, size = [], 0
            current.append(line)
            size += len(line)
        if current:
            part += 1
            chunks.append((f"{path}#part{part}", "".join(current)))
        return chunks

    def _user_prompt(self, label: str, text: str, deep: bool,
                     intel_brief: str = "",
                     kb_snippet: str = "",
                     stage7_section: str = "") -> str:
        notice = (
            "NOTE: the following is decompiled PSEUDO-SOURCE recovered from "
            "bytecode, NOT the original Solidity. It is an approximate "
            "representation; treat identifiers/structure as unreliable."
            if self.material_is_pseudo
            else ""
        )
        suffix = DEEP_DIVE_SUFFIX if deep else BASIC_SCAN_SUFFIX
        intel_section = (
            f"\n=== UNTRUSTED STATIC INTEL (deterministic extraction; may be "
            f"incomplete — verify every claim against the code) ===\n{intel_brief}"
            f"\n=== END STATIC INTEL ===\n"
            if intel_brief else ""
        )
        kb_section = (
            f"\n=== UNTRUSTED KB CONTEXT: historical vulnerability mechanisms "
            f"(reference data, not findings; explain applicability or discard) ===\n"
            f"{kb_snippet}\n=== END KB CONTEXT ===\n"
            if kb_snippet else ""
        )
        stage7_section = (
            f"\n=== STATIC CROSS-FUNCTION HYPOTHESES (Stage 7; inferred paths "
            f"and candidate invariants — investigate, confirm or refute with "
            f"code evidence; they are hypotheses, not findings) ===\n"
            f"{stage7_section}\n=== END CROSS-FUNCTION HYPOTHESES ===\n"
            if stage7_section else ""
        )
        return f"""{notice}{intel_section}{kb_section}{stage7_section}

{suffix}

=== UNTRUSTED CONTRACT DATA: {label} ===
{text}
=== END UNTRUSTED CONTRACT DATA ===

Audit the code above for your focus area. Respond with ONLY the strict JSON
object described in your instructions."""

    async def analyze(self, budget: AuditBudget, material: AnalysisMaterial) -> AgentResult:
        result = AgentResult(agent=self.name)
        self.material_is_pseudo = material.is_pseudo_source

        if not material.segments:
            result.skipped_reason = "no material provided"
            return result

        text = material.text()
        deep = any(kw.lower() in text.lower() for kw in self.keywords)

        work: list[tuple[str, str]] = []
        total = 0
        for path, content in material.segments.items():
            for label, chunk in self._chunk(path, content):
                if total + len(chunk) > self.max_total_chars:
                    result.errors.append(
                        f"analysis truncated: exceeded {self.max_total_chars} chars; "
                        f"unanalyzed remainder of {path}"
                    )
                    break
                work.append((label, chunk))
                total += len(chunk)

        intel = getattr(material, "intel", None)
        intel_brief = ""
        try:
            if intel is not None:
                intel_brief = render_intel_brief(intel, self.focus)
        except Exception as exc:  # intel is an optimization, never a blocker
            logger.warning("intel render failed for %s: %s", self.name, exc)

        # Stage 7: static cross-function hypotheses (inferred paths + candidate
        # invariants) attached to the material by the orchestrator. Injected
        # as an investigate/refute hint — never as findings.
        stage7_section = ""
        try:
            paths = getattr(material, "paths", None) or []
            invariants = getattr(material, "invariants", None) or []
            if paths or invariants:
                from agentsafe.intel.invariants import render_invariants
                from agentsafe.intel.paths import render_paths
                parts = []
                if paths:
                    parts.append(render_paths(paths))
                if invariants:
                    parts.append(render_invariants(invariants))
                stage7_section = "\n\n".join(parts)
        except Exception as exc:  # Stage 7 hints are optional context
            logger.warning("stage7 render failed for %s: %s", self.name, exc)

        for label, chunk in work:
            kb_snippet = ""
            kb_refs: list[str] = []
            try:
                kb = getattr(material, "kb", None)
                if kb is not None:
                    records = kb.search(
                        query=chunk[:4000] + " " + " ".join(self.keywords),
                        focus=self.focus, limit=2)
                    kb_snippet = render_kb_snippets(records)
                    # Stage 5: attach retrieval provenance (record id or
                    # source url) to findings produced from this chunk.
                    # References are context pointers, NOT confidence.
                    for r in records:
                        ref = r.get("id") or r.get("external_record_id") \
                            or r.get("source_url")
                        if ref and ref not in kb_refs:
                            kb_refs.append(ref)
            except Exception as exc:  # KB is context, never a blocker
                logger.warning("kb search failed for %s: %s", self.name, exc)
            messages = [
                {"role": "system", "content": system_prompt(self.focus)},
                {"role": "user", "content": self._user_prompt(
                    label, chunk, deep, intel_brief=intel_brief,
                    kb_snippet=kb_snippet, stage7_section=stage7_section)},
            ]
            try:
                payload, call = await self._router.complete_json(
                    budget, messages, LLMFindingsPayload
                )
            except Exception as exc:  # budget/provider/schema errors are per-segment
                result.errors.append(f"{label}: {type(exc).__name__}: {exc}")
                continue
            result.segments_analyzed += 1
            for f in payload.findings:
                result.findings.append(self._to_finding(f, label, call, kb_refs))

        if result.errors and not result.findings and result.segments_analyzed == 0:
            result.skipped_reason = "; ".join(result.errors[:3])
        return result

    def _to_finding(self, p: LLMFindingPayload, label: str, call: Any,
                    kb_refs: list[str] | None = None) -> Finding:
        return Finding(
            title=p.title,
            severity=p.severity,  # type: ignore[arg-type]
            status=FindingStatus.LLM_SUGGESTED,
            source=[self.name],
            detector_id=None,
            swc_id=p.swc_id,
            cwe_id=p.cwe_id,
            description=p.description,
            evidence=p.evidence,
            recommendation=p.recommendation,
            preconditions=p.preconditions,
            attack_scenario=p.attack_scenario,
            impact=p.impact,
            file_path=p.file_path or (label.split("#part")[0] or None),
            line_start=p.line_start,
            line_end=p.line_end,
            confidence=p.confidence,
            # Stage 5: provenance-only references; never confidence.
            knowledge_references=list(kb_refs or []),
            metadata={
                "agent": self.name,
                "llm_provider": call.provider,
                "llm_model": call.model,
                "pseudo_source": self.material_is_pseudo,
            },
        )


def split_segments(files: Sequence[Any]) -> dict[str, str]:
    """SourceBundle.files -> segments dict (path -> content)."""
    return {sf.path: sf.content for sf in files}
