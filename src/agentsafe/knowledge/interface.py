"""Phase 7 — the stable retrieval interface for specialist agents.

One structured, versioned entry point that future audit-engine specialists can
call for BOTH discovery (find relevant mechanisms) and independent validation
(corroborate or refute a claim), without replacing the knowledge base. It wraps
the existing hybrid search + context matching + counterexample retrieval and
returns a normalized response and explicit retrieval metadata.

Design guarantees:
  * structured request (agent identity, category, contract context, solc,
    function/code context, state vars, external interactions, depth, intent);
  * normalized response (records, source references, technical explanations,
    exploit patterns, counterexamples, validation status, retrieval metadata);
  * honest: retrieved records are HISTORICAL SUPPORTING EVIDENCE, never an
    automatic verdict, and no field is fabricated;
  * compatible: works with the Neon hybrid store (`solc` + `context`) and the
    JSONL fallback KB (extra kwargs degrade away).

Existing consumers are unchanged (Phase 5/6 in `agents/base.py`, corroboration
in `orchestrator.py`); this interface is what the next phase can adopt directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentsafe.knowledge.context import ContractContext
from agentsafe.knowledge.falsepositives import retrieve_counterexamples

INTERFACE_VERSION = "1.0"

# Fields each normalized record exposes. Documented via describe().
_RECORD_VIEW_FIELDS = (
    "id", "external_record_id", "title", "category", "subcategory", "severity",
    "validation_status", "quality_status", "claim", "source",
    "technical_explanation", "mechanism", "exploit_pattern", "remediation",
    "code", "counterexample", "retrieval",
)


@dataclass
class KnowledgeRequest:
    """A structured knowledge request from a specialist agent."""

    query: str = ""
    agent: str | None = None                 # agent identity (e.g. "oracle")
    category: str | None = None
    profile: str | None = None               # overrides agent-derived profile
    depth: int = 3                           # requested retrieval depth (limit)
    intent: str = "discovery"                # "discovery" | "validation"
    solc: str | None = None
    code: str = ""                           # function / code context
    functions: list[str] = field(default_factory=list)
    state_vars: list[str] = field(default_factory=list)
    external_interactions: list[str] = field(default_factory=list)
    context: ContractContext | None = None
    # optional hard filters
    kb_groups: list[str] | None = None
    categories: list[str] | None = None
    tags: list[str] | None = None
    sources: list[str] | None = None
    include_counterexamples: bool = True
    min_relevance: float = 0.0

    def effective_profile(self) -> str | None:
        return self.profile or self.agent

    def to_context(self) -> ContractContext:
        """Merge an explicit context with any structured fields on the request
        (never mutates the caller's context)."""
        src = self.context
        ctx = ContractContext(
            solc=(src.solc if src else None),
            pragma=list(src.pragma) if src else [],
            contracts=list(src.contracts) if src else [],
            functions=list(src.functions) if src else [],
            state_vars=list(src.state_vars) if src else [],
            external_calls=list(src.external_calls) if src else [],
            token_standards=list(src.token_standards) if src else [],
            protocol_traits=list(src.protocol_traits) if src else [],
            attack_surface=list(src.attack_surface) if src else [],
            categories=list(src.categories) if src else [],
        )
        if self.solc and not ctx.solc:
            ctx.solc = self.solc
        ctx.functions = _merge(ctx.functions, self.functions)
        ctx.state_vars = _merge(ctx.state_vars, self.state_vars)
        ctx.external_calls = _merge(ctx.external_calls, self.external_interactions)
        if self.category:
            ctx.categories = _merge([self.category], ctx.categories)
        return ctx

    def query_text(self, ctx: ContractContext) -> str:
        parts = [self.query, str(self.code or "")[:4000], self.category,
                 " ".join(ctx.token_standards), " ".join(ctx.protocol_traits),
                 " ".join(self.functions[:10]), " ".join(self.state_vars[:10]),
                 " ".join(self.external_interactions[:8]), ctx.solc or ""]
        return " ".join(p for p in parts if p)


@dataclass
class KnowledgeResponse:
    records: list[dict[str, Any]] = field(default_factory=list)
    counterexamples: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"records": self.records, "counterexamples": self.counterexamples,
                "metadata": self.metadata}

    def validated(self) -> list[dict[str, Any]]:
        """Records carrying independent validation (curated/reproduced) — for
        the validation use case."""
        return [r for r in self.records
                if str(r.get("validation_status") or "").lower()
                in ("curated", "reproduced")]


def _merge(a: list[str], b: list[str], cap: int = 20) -> list[str]:
    out = [str(x) for x in (a or [])]
    for x in (b or []):
        s = str(x)
        if s not in out:
            out.append(s)
    return out[:cap]


def _view(r: dict[str, Any]) -> dict[str, Any]:
    """Normalize one record to the stable interface view."""
    return {
        "id": r.get("id"),
        "external_record_id": r.get("external_record_id"),
        # Older datasets (v1) carry no `title`; fall back to the mechanism so a
        # consumer always has a label (never fabricated — it is the record's own).
        "title": r.get("title") or (str(r.get("mechanism") or "")[:120] or None),
        "category": r.get("category"),
        "subcategory": r.get("subcategory"),
        "severity": r.get("severity"),
        "validation_status": r.get("verification_status"),
        "quality_status": r.get("quality_status"),
        "claim": r.get("quality_claim"),
        "source": {
            "name": r.get("source_name") or r.get("source"),
            "url": r.get("source_url") or r.get("url"),
            "external_record_id": r.get("external_record_id"),
        },
        "technical_explanation": r.get("root_cause") or r.get("mechanism"),
        "mechanism": r.get("mechanism"),
        "exploit_pattern": {
            "preconditions": r.get("preconditions") or [],
            "attack_entry": r.get("attack_entry"),
            "attack_scenario": r.get("attack_scenario") or r.get("exploit_sequence"),
            "impact": r.get("impact"),
        },
        "remediation": r.get("remediation"),
        "code": {"vulnerable": r.get("vulnerable_code"),
                 "corrected": r.get("corrected_code")},
        "counterexample": {k: r.get(k) for k in (
            "why_safe", "fp_patterns", "evidence_required", "known_limitations",
            "security_pattern", "safe_code") if r.get(k)},
        "retrieval": r.get("_retrieval") or {},
    }


def retrieve(kb: Any, request: KnowledgeRequest) -> KnowledgeResponse:
    """Execute a structured knowledge request against any store."""
    if kb is None:
        return KnowledgeResponse(metadata={"error": "no knowledge base"})
    ctx = request.to_context()
    profile = request.effective_profile()
    focus = "validation" if request.intent == "validation" else (request.category or "")
    depth = max(1, int(request.depth))
    query = request.query_text(ctx)

    status: dict[str, Any] = {}
    kwargs: dict[str, Any] = {
        "focus": focus, "limit": depth, "profile": profile,
        "kb_groups": request.kb_groups, "categories": request.categories,
        "tags": request.tags, "sources": request.sources,
        "solc": ctx.solc, "context": ctx.to_match_dict(),
        "min_relevance": request.min_relevance, "status": status,
    }
    try:
        raw = kb.search(query, **kwargs)
    except TypeError:
        # Fallback KB without context-aware kwargs.
        raw = kb.search(query, focus=focus, limit=depth, profile=profile,
                        kb_groups=request.kb_groups, categories=request.categories)
    records = [_view(r) for r in raw or []]

    counterexamples: list[dict[str, Any]] = []
    if request.include_counterexamples:
        ctext = request.code or request.query
        if ctext or request.category:
            try:
                crecs = retrieve_counterexamples(
                    kb, text=ctext, context=ctx, category=request.category,
                    limit=depth if request.intent == "discovery" else max(depth, 3))
                counterexamples = [_view(r) for r in crecs or []]
            except Exception:  # noqa: BLE001 - counterexamples are additive
                counterexamples = []

    mode = status.get("mode") or (
        "hybrid" if getattr(kb, "embedding_model", None) is not None
        else "lexical")
    degraded = bool(status.get("degraded", False))
    metadata = {
        "interface_version": INTERFACE_VERSION,
        "mode": mode,
        "degraded": degraded,
        "vector_used": status.get("vector_used"),
        "lexical_used": status.get("lexical_used"),
        "degradation_reason": status.get("reason"),
        "intent": request.intent,
        "agent": request.agent,
        "profile": profile,
        "depth": depth,
        "solc": ctx.solc,
        "context_present": bool(ctx.functions or ctx.state_vars
                                or ctx.external_calls or ctx.protocol_traits),
        "filters": {"kb_groups": request.kb_groups,
                    "categories": request.categories,
                    "tags": request.tags, "sources": request.sources},
        "record_count": len(records),
        "counterexample_count": len(counterexamples),
        "validated_count": sum(
            1 for r in records
            if str(r.get("validation_status") or "").lower()
            in ("curated", "reproduced")),
        "retrieved_at": datetime.now(UTC).isoformat(),
        "supporting_evidence": True,
        "note": (
            (f"DEGRADED RETRIEVAL ({status.get('reason')}) - results may be "
             "incomplete. " if degraded else "")
            + "Retrieved records are historical supporting intelligence, "
              "never automatic proof of a vulnerability. Confirm the actual "
              "code and execution context before reporting."),
    }
    return KnowledgeResponse(records=records, counterexamples=counterexamples,
                             metadata=metadata)


def describe() -> dict[str, Any]:
    """Machine-readable description of the interface (for the next engine
    phase and docs)."""
    return {
        "interface_version": INTERFACE_VERSION,
        "entrypoint": "agentsafe.knowledge.interface.retrieve(kb, KnowledgeRequest)",
        "request_fields": [
            "query", "agent", "category", "profile", "depth", "intent",
            "solc", "code", "functions", "state_vars", "external_interactions",
            "context", "kb_groups", "categories", "tags", "sources",
            "include_counterexamples", "min_relevance",
        ],
        "intents": ["discovery", "validation"],
        "response_fields": ["records", "counterexamples", "metadata"],
        "record_view_fields": list(_RECORD_VIEW_FIELDS),
        "guarantees": [
            "historical records are supporting evidence, never a verdict",
            "no fabricated fields or scores",
            "works with the Neon hybrid store and the JSONL fallback",
        ],
    }


__all__ = [
    "INTERFACE_VERSION",
    "KnowledgeRequest",
    "KnowledgeResponse",
    "describe",
    "retrieve",
]
