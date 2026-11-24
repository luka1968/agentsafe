"""Stage B — complete source-coverage accounting.

Every submitted source file and every analyzable segment must be accounted for,
and a partial analysis must never be presented as a complete one. This module
turns "which segments did agents actually analyze" into an explicit, auditable
record:

- every file and every chunk (the SAME chunker the agents use);
- which segments were analyzed by at least one agent, and which were not;
- how many functions fall inside un-analyzed segments (the concrete code that
  was never examined);
- an explicit ``is_complete`` flag the pipeline uses to demote ``audit_state``.

Honesty is structural: an empty/un-analyzed set is reported as such, never
rounded up to "covered". The label space is shared with ``agents.base`` so no
segment can hide between two different chunkers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from agentsafe.agents.base import MAX_SEGMENT_CHARS, chunk_segment

__all__ = ["CoverageReport", "build_coverage"]

logger = logging.getLogger("agentSAFE.coverage")


@dataclass
class CoverageReport:
    files: list[str] = field(default_factory=list)
    total_segments: int = 0
    analyzed_segments: int = 0
    unanalyzed_segments: list[str] = field(default_factory=list)
    total_functions: int = 0
    uncovered_functions: list[str] = field(default_factory=list)
    per_file: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        return (self.analyzed_segments / self.total_segments) if self.total_segments else 1.0

    @property
    def is_complete(self) -> bool:
        return not self.unanalyzed_segments

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": list(self.files),
            "total_segments": self.total_segments,
            "analyzed_segments": self.analyzed_segments,
            "unanalyzed_segments": list(self.unanalyzed_segments),
            "unanalyzed_segments_count": len(self.unanalyzed_segments),
            "total_functions": self.total_functions,
            "uncovered_functions": list(self.uncovered_functions[:60]),
            "uncovered_functions_count": len(self.uncovered_functions),
            "per_file": self.per_file,
            "coverage_ratio": round(self.coverage_ratio, 4),
            "is_complete": self.is_complete,
            "notes": list(self.notes),
        }


def _function_coverage(
    segments: dict[str, str],
    seg_index: dict[str, tuple[str, int, int]],
    analyzed: set[str],
) -> tuple[int, list[str]]:
    """Map every extracted function to the segment that contains it and report
    the functions whose segment was never analyzed. Per-file intel extraction
    binds functions to their file (the whole-set extractor carries no path)."""
    from agentsafe.intel.extract import extract_contract_intel

    labels_by_path: dict[str, list[tuple[str, int, int]]] = {}
    for label, (path, start, end) in seg_index.items():
        labels_by_path.setdefault(path, []).append((label, start, end))

    total = 0
    uncovered: list[str] = []
    for path, content in segments.items():
        try:
            intel_p = extract_contract_intel({path: content})
        except Exception as exc:  # coverage is an aid; never blocks a report
            logger.debug("coverage: intel extraction failed for %s: %s", path, exc)
            continue
        labels = sorted(labels_by_path.get(path, []), key=lambda t: t[1])
        for c in intel_p.contracts:
            for f in c.functions:
                total += 1
                line = f.line_start or 1
                label = next((lbl for lbl, s, e in labels if s <= line <= e), None)
                if label is None and labels:
                    label = labels[0][0]
                if label is not None and label in analyzed:
                    continue
                uncovered.append(f"{c.name}.{f.name} ({path}:{line})")
    return total, uncovered


def build_coverage(
    segments: dict[str, str] | None,
    analyzed_labels: Any,
    *,
    intel: Any | None = None,
    max_chars: int = MAX_SEGMENT_CHARS,
) -> CoverageReport:
    """Build the coverage record for one audit.

    ``analyzed_labels`` is the union of the segment labels reported by every
    agent's ``analyzed_labels`` (only segments a call actually succeeded on)."""
    segs = segments or {}
    analyzed = {str(label) for label in (analyzed_labels or ())}
    rep = CoverageReport(files=list(segs.keys()))

    seg_index: dict[str, tuple[str, int, int]] = {}
    for path, content in segs.items():
        for label, _text, start, end in chunk_segment(path, content, max_chars):
            seg_index[label] = (path, start, end)

    rep.total_segments = len(seg_index)
    rep.analyzed_segments = sum(1 for label in seg_index if label in analyzed)
    rep.unanalyzed_segments = sorted(lbl for lbl in seg_index if lbl not in analyzed)

    for path in segs:
        labels = [lbl for lbl, (p, _s, _e) in seg_index.items() if p == path]
        rep.per_file[path] = {
            "segments": len(labels),
            "analyzed": sum(1 for lbl in labels if lbl in analyzed),
            "unanalyzed": sorted(lbl for lbl in labels if lbl not in analyzed),
        }

    if intel is not None and segs:
        rep.total_functions, rep.uncovered_functions = _function_coverage(
            segs, seg_index, analyzed
        )

    if rep.total_segments and not rep.is_complete:
        rep.notes.append(
            f"{rep.analyzed_segments}/{rep.total_segments} source segment(s) were "
            "analyzed by at least one agent"
        )
    if not analyzed and rep.total_segments:
        rep.notes.append("no agent analyzed any source segment")
    return rep
