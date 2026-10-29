"""Core data models for agentSAFE MCP.

Every finding from any analyzer (Slither, Aderyn, Mythril, Heimdall, LLM agents)
MUST normalize to `Finding`. Status values never imply "contract is safe".
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from agentsafe import CHAIN_ID, REPORT_DISCLAIMER

_ADDRESS_RE = re.compile(r"^0[xX][0-9a-fA-F]{40}$")


def normalize_address(value: str) -> str:
    """Validate and normalize a 20-byte EVM address to lowercase 0x-hex."""
    v = (value or "").strip()
    if not _ADDRESS_RE.match(v):
        raise ValueError(f"invalid EVM address: {value!r} (expected '0x' + 40 hex characters)")
    return v.lower()


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    """Stage 9: stable finding taxonomy (subset of SWC topics, evidence-driven
    assignment by the proposing agent or mapped from detector ids)."""

    ACCESS_CONTROL = "access_control"
    REENTRANCY = "reentrancy"
    ARITHMETIC = "arithmetic"
    ACCOUNTING = "accounting"
    LOGIC_ERROR = "logic_error"
    ORACLE = "oracle"
    PROXY = "proxy"
    TOKEN = "token"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    """Finding lifecycle states (strict state machine).

    Internal entry states (never present in a final report):
    - tool_detected: a deterministic tool reported it (not yet proven exploitable)
    - llm_suggested: LLM hypothesis entering validation

    Final states (the only ones a customer-facing report may contain):
    - confirmed: independently corroborated (tool + LLM agreement at the
      same location, or deterministic corroboration). Corroboration means
      "independently supported by evidence", never "proven exploitable".
    - potential: complete evidence, neither confirmed nor refuted. Credible
      hypothesis requiring human judgment.
    - informational: validated as standard/theoretical/informational-grade
      (e.g. standard ERC-20 semantics, purely theoretical arithmetic issue).
    - rejected: contradicted by deterministic source analysis or missing
      required evidence. Kept in reports for auditability, excluded from
      severity headlines.
    - needs_manual_review: validation inconclusive (missing location,
      untraceable evidence). Human input required.

    None of these states may ever be used to claim "the contract is safe".
    """

    TOOL_DETECTED = "tool_detected"
    LLM_SUGGESTED = "llm_suggested"
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFORMATIONAL = "informational"
    REJECTED = "rejected"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"

    @classmethod
    def final_states(cls) -> frozenset[FindingStatus]:
        """States valid in a customer-facing report."""
        return frozenset(
            {
                cls.CONFIRMED,
                cls.POTENTIAL,
                cls.INFORMATIONAL,
                cls.REJECTED,
                cls.NEEDS_MANUAL_REVIEW,
            }
        )


class TaskState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class StageState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class KnowledgeReference(BaseModel):
    """Stage 9: structured knowledge-base reference attached to a finding.

    Provenance only — a reference records which historical case or document
    the agent consulted, never a verdict and never a confidence signal.
    Unknown subfields are omitted (None), never invented.
    """

    model_config = ConfigDict(extra="forbid")

    knowledge_id: str | None = None
    source_name: str | None = None
    source_url: str | None = None
    title: str | None = None
    relevance_reason: str | None = None


class Finding(BaseModel):
    """A single normalized audit finding. See E_VERSION_PLAN section 5."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    title: str = Field(min_length=1, max_length=300)
    finding_id: str = Field(default="", max_length=32)
    severity: Severity
    proposed_severity: Severity | None = None
    status: FindingStatus
    source: list[str] = Field(min_length=1)
    detector_id: str | None = None
    swc_id: str | None = Field(default=None, max_length=16)
    cwe_id: str | None = Field(default=None, max_length=16)
    description: str = Field(min_length=1)
    evidence: str = ""
    recommendation: str = ""
    preconditions: str = ""
    attack_scenario: str = ""
    impact: str = ""
    file_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    # Section 7 traceability marker, set by the validation agent:
    #   verified   - location comes from a trusted analyzer mapping, or the
    #                LLM evidence quote was located verbatim in that file/line
    #   unverified - location plausibly correct but could not be verified
    #                (decompiled pseudo-source, short evidence, no filename)
    #   unavailable - no file and no line could be determined
    # Never guessed; absent (None) means "not assessed".
    location_status: Literal["verified", "unverified", "unavailable"] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    # Stage 5: KB references attached to the finding. These are *retrieval
    # provenance* (which historical cases the agent consulted), NOT proof of
    # a current vulnerability and NOT a confidence signal. A reference may be
    # a KB record id or a source_url when the store does not expose ids.
    knowledge_references: list[str] = Field(default_factory=list)
    # Stage 9: structured KB references (superset of knowledge_references;
    # populated when the store exposes structured metadata). Provenance only.
    knowledge_reference_details: list[KnowledgeReference] = Field(default_factory=list)
    # Stage 9: structured taxonomy/location/validation fields. All optional
    # with safe defaults so existing consumers keep working.
    category: FindingCategory = FindingCategory.UNKNOWN
    affected_functions: list[str] = Field(default_factory=list)
    state_dependencies: list[str] = Field(default_factory=list)
    invariant_violated: str | None = None
    validation_method: str | None = None   # e.g. "deterministic_rules" | "independent_tool_corroboration" | "targeted_test" | "manual_review"
    validation_result: str | None = None   # e.g. "not_executed" | "passed" | "failed" | "needs_manual_review"
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _ensure_finding_id(self) -> Finding:
        """Every finding carries a unique, deterministic id derived from its
        origin (source + detector + claim + location), so reports are
        reproducible and duplicates are traceable across runs."""
        if not self.finding_id:
            basis = "|".join(
                [
                    ",".join(sorted(self.source)),
                    self.detector_id or "",
                    self.title,
                    self.file_path or "",
                    str(self.line_start or 0),
                ]
            )
            self.finding_id = "f-" + hashlib.sha1(basis.encode()).hexdigest()[:12]
        return self

    @field_validator("source")
    @classmethod
    def _validate_source(cls, v: list[str]) -> list[str]:
        cleaned = [s.strip().lower() for s in v if s and s.strip()]
        if not cleaned:
            raise ValueError("source must contain at least one non-empty tool/agent name")
        return cleaned

    @field_validator("evidence")
    @classmethod
    def _validate_evidence(cls, v: str, info) -> str:
        status = info.data.get("status")
        # Entry states may arrive without evidence text (tools), rejected
        # findings may be rejected precisely for lacking evidence, and
        # needs_manual_review may be incomplete - that is its purpose. Every
        # state presented as actionable (confirmed/potential/informational)
        # MUST carry evidence: findings without evidence must never be
        # presented as actionable.
        exempt = {
            FindingStatus.TOOL_DETECTED,
            FindingStatus.LLM_SUGGESTED,
            FindingStatus.REJECTED,
            FindingStatus.NEEDS_MANUAL_REVIEW,
        }
        if status not in exempt and not v.strip():
            raise ValueError(
                "evidence is required for actionable statuses "
                "(confirmed/potential/informational); findings without "
                "evidence must never be presented as actionable"
            )
        return v

    @field_validator("line_end")
    @classmethod
    def _validate_line_range(cls, v: int | None, info) -> int | None:
        start = info.data.get("line_start")
        if v is not None and start is not None and v < start:
            raise ValueError("line_end must be >= line_start")
        return v

    def merge_key(self) -> tuple[str, str | None, str | None, int | None, str]:
        """Deterministic dedup key.

        Detector findings (e.g. Slither) with the same detector_id at the same
        location merge even when titles differ; semantic findings (LLM, no
        detector_id) additionally key on the normalized title. The orchestrator
        combines this with evidence similarity - this key is never the sole
        basis for claiming two findings are identical.
        """
        if self.detector_id:
            return (
                "detector",
                self.detector_id.strip().lower(),
                (self.file_path or "").lower(),
                self.line_start,
                "",  # title intentionally excluded for detector findings
            )
        return (
            "semantic",
            None,
            (self.file_path or "").lower(),
            self.line_start,
            self.title.strip().lower(),
        )


class AuditRequest(BaseModel):
    """Validated audit request. Mainnet only."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    address: str
    chain: Literal["ethereum-mainnet"] = CHAIN_ID

    @field_validator("address")
    @classmethod
    def _validate_address(cls, v: str) -> str:
        return normalize_address(v)


class StageStatus(BaseModel):
    """Execution state of one pipeline stage."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    state: StageState = StageState.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_code: str | None = None
    detail: str | None = None


class TaskStatus(BaseModel):
    """Reconstructable task state (source of truth: GitHub Actions run + artifacts)."""

    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=8, max_length=64)
    address: str | None = None
    state: TaskState = TaskState.QUEUED
    run_id: int | None = None
    stages: list[StageStatus] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    error_code: str | None = None
    # x402 payment binding (Phase 12): paid=True only after a payment passed
    # official SDK verification for this task's dispatch; payment_ref is the
    # canonical fingerprint of the verified payment payload (replay ledger key).
    paid: bool = False
    payment_ref: str | None = None

    def stage(self, name: str) -> StageStatus:
        for s in self.stages:
            if s.name == name:
                return s
        raise KeyError(name)


class LLMUsage(BaseModel):
    """LLM call accounting for one audit. Hard budget enforcement lives in router."""

    total_calls: int = 0
    total_prompt_tokens: int | None = None
    total_completion_tokens: int | None = None
    providers_used: list[str] = Field(default_factory=list)
    models_used: list[str] = Field(default_factory=list)
    failed_calls: int = 0


class ReportSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    tools_executed: list[str] = Field(default_factory=list)
    tools_failed: list[str] = Field(default_factory=list)
    # Clear partial-analysis status for the static-analysis pipeline
    # (never inferred from tool invocation alone):
    #   full        - every source tool ran and returned a parsable result
    #   partial     - some tools ran, others failed; missing results are NOT
    #                 evidence of safety
    #   unavailable - the static-analysis stage itself errored out
    #   skipped     - no verified source (closed-source path)
    static_analysis_status: Literal["full", "partial", "unavailable", "skipped"] = "skipped"


class ToolExecution(BaseModel):
    """Structured diagnostic for ONE analyzer invocation (Section 5).

    Captured for every tool attempt regardless of outcome: exit code,
    duration, tool/compiler versions, failure category and output tails.
    ``executed=True`` means a parsable result was produced - never merely
    that the binary was invoked.
    """

    model_config = ConfigDict(extra="forbid")

    tool: str
    kind: Literal["source", "bytecode"] = "source"
    executed: bool
    exit_code: int | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    tool_version: str | None = None
    compiler_version: str | None = None
    # Documented failure taxonomy (agentsafe.analyzers.source categories):
    #   not_installed | timeout | spawn_error | no_output | compile_error |
    #   parse_error | tool_error | nonzero_exit_no_findings | None (success)
    failure_category: str | None = None
    error: str | None = None
    stderr_tail: str | None = None
    stdout_tail: str | None = None
    findings_count: int = Field(default=0, ge=0)


class AuditReport(BaseModel):
    """Full audit report persisted as report.json artifact."""

    model_config = ConfigDict(extra="forbid")

    address: str
    chain: Literal["ethereum-mainnet"] = CHAIN_ID
    task_id: str | None = None
    # Human-facing report identifier for the customer-facing HTML/PDF cover
    # page (the task id when dispatched by the service, else a derived id).
    report_id: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    is_verified_source: bool = False
    # Scope/methodology data (Section 8): what was actually analyzed.
    compiler_version: str = ""
    analyzed_files: list[str] = Field(default_factory=list)
    summary: ReportSummary = Field(default_factory=ReportSummary)
    findings: list[Finding] = Field(default_factory=list)
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    llm_usage: LLMUsage = Field(default_factory=LLMUsage)
    limitations: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    execution_time_seconds: float | None = None
    disclaimer: str = REPORT_DISCLAIMER
    # Stage 7: cross-function path hypotheses + candidate invariants with
    # explicit results (holds_under_tested_conditions/violated/inconclusive/
    # not_applicable). Evidence-backed; never presented as findings.
    invariant_checks: list[dict[str, Any]] = Field(default_factory=list)
    attack_paths: list[dict[str, Any]] = Field(default_factory=list)
    # Stage 8: targeted test runs (isolated sandbox). never treated as proof
    # when not_executed; failed != unsafe (honesty by construction).
    targeted_test_results: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("address")
    @classmethod
    def _validate_address(cls, v: str) -> str:
        return normalize_address(v)
