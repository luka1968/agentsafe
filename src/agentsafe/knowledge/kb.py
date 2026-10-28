"""Retrieval-based security knowledge base.

Mission contract (docs/baseline.md, upgrade target 2):
- Small, high-quality, *versioned* JSONL dataset first. Every record carries
  provenance (source, URL), category, root cause, preconditions, exploit
  sequence, impact, remediation, and its own keywords.
- Retrieval is lexical (term-frequency scoring with normalization) — no
  external service, no vector DB, fine-tuning explicitly out of scope for v1.
- Retrieved records are UNTRUSTED CONTEXT: the renderer wraps them in
  untrusted markers and forces an applicability argument per record.
- Dataset validation is strict: a record missing provenance or mechanism is a
  load-time error (fail fast on bad data, never silently degrade quality).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("agentSAFE.knowledge")

DATASET_VERSION = 1
_REQUIRED_FIELDS = ("id", "source", "url", "category", "mechanism",
                    "root_cause", "preconditions", "impact", "remediation",
                    "keywords")
_STOPWORDS = {
    "the", "a", "an", "of", "to", "in", "on", "for", "and", "or", "is",
    "are", "be", "that", "this", "it", "as", "with", "from", "by", "at",
    "can", "may", "if", "not", "no", "when", "which", "before", "after",
    "into", "during", "using", "use", "used", "its",
}

# Focus areas -> KB categories that are most relevant for that agent.
_FOCUS_CATEGORIES = {
    "access_control": {"access-control", "initialization", "privileged",
                       "proxy", "authorization"},
    "fund_flow": {"reentrancy", "accounting", "unhandled-return",
                  "token-transfer", "cei", "donation"},
    "business_logic": {"oracle", "rounding", "governance", "flash-loan",
                       "bridge", "approval", "tokenomics", "accounting"},
}


def _tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower())
            if t not in _STOPWORDS and len(t) > 1]


@dataclass
class KnowledgeBase:
    """In-memory versioned KB with lexical retrieval."""

    records: list[dict[str, Any]] = field(default_factory=list)
    version: int = DATASET_VERSION
    _index: list[tuple[dict[str, Any], list[str], dict[str, int]]] = field(
        default_factory=list, repr=False)

    # -- loading -------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "KnowledgeBase":
        p = Path(path)
        if not p.exists():
            logger.warning("knowledge base file missing: %s", p)
            return cls(records=[])
        records: list[dict[str, Any]] = []
        with p.open("r", encoding="utf-8") as fh:
            for ln, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{p.name}:{ln}: invalid JSONL: {exc}") from exc
                missing = [k for k in _REQUIRED_FIELDS if k not in rec]
                if missing:
                    raise ValueError(
                        f"{p.name}:{ln}: record {rec.get('id', '?')} missing "
                        f"provenance/quality fields: {missing}")
                if rec.get("keywords") and not isinstance(rec["keywords"], list):
                    raise ValueError(f"{p.name}:{ln}: keywords must be a list")
                records.append(rec)
        kb = cls(records=records)
        kb._build_index()
        logger.info("knowledge base loaded: %d records (v%s) from %s",
                    len(records), DATASET_VERSION, p.name)
        return kb

    @classmethod
    def load_default(cls) -> "KnowledgeBase":
        default = Path(__file__).parent / "dataset" / f"v{DATASET_VERSION}.jsonl"
        return cls.load(default)

    def _build_index(self) -> None:
        self._index = []
        for rec in self.records:
            corpus = " ".join([
                rec.get("id", ""), rec.get("category", ""),
                rec.get("protocol_type", ""), rec.get("mechanism", ""),
                rec.get("root_cause", ""), " ".join(rec.get("preconditions", [])),
                " ".join(rec.get("keywords", [])),
            ])
            toks = _tokenize(corpus)
            tf: dict[str, int] = {}
            for t in toks:
                tf[t] = tf.get(t, 0) + 1
            self._index.append((rec, toks, tf))

    # -- retrieval -------------------------------------------------------------
    def search(self, query: str, focus: str = "", limit: int = 3) -> list[dict[str, Any]]:
        """Lexical retrieval, reranked by focus-category affinity.
        Query terms come from the agent focus keywords + the contract text."""
        if not self._index:
            return []
        q_terms = _tokenize(query)
        if not q_terms:
            return []
        n_docs = len(self._index)
        df: dict[str, int] = {}
        for _, toks, _tf in self._index:
            for t in set(toks):
                df[t] = df.get(t, 0) + 1

        focus_cats = _FOCUS_CATEGORIES.get(
            next((k for k in _FOCUS_CATEGORIES if k.split("_")[0] in focus.lower()),
                 "access_control"), set())

        scored: list[tuple[float, dict[str, Any]]] = []
        for rec, toks, tf in self._index:
            score = 0.0
            for t in set(q_terms):
                if t in tf:
                    idf = 1.0 + (n_docs / (1 + df.get(t, 0)))
                    score += idf * (1.0 + tf[t] / max(1, len(toks)))
            if rec.get("category", "") in focus_cats:
                score *= 1.6  # focus affinity rerank
            if score > 0:
                scored.append((score, rec))
        scored.sort(key=lambda x: (-x[0], x[1].get("id", "")))
        return [rec for _, rec in scored[:limit]]
