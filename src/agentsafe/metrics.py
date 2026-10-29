"""Operational metrics for Stage 11 — security & operational controls.

Purpose: track import failures, retrieval latency, model usage and agent
performance WITHOUT ever recording secrets, private source code, task ids,
addresses or any PII. The metrics surface is deliberately numeric: counters,
durations and category labels only.

- ``get_metrics()`` returns a process-wide singleton (thread-safe).
- ``snapshot()`` returns a plain dict for logging / JSONL sink / /healthz.
- ``MetricsSink`` appends snapshots as JSONL to a configurable path; safe to
  use under concurrency (single append lock). Never contains payloads.

Keys are grouped:

    import_{success|failed|skipped_duplicate|records}
    import_embedding_{calls|failed}        # embedder invocations
    retrieval_{calls|latency_ms_sum|latency_ms_max|vector_fallback|neon_fallback}
    llm_{calls|failed|tokens_in|tokens_out}  # live LLM provider usage
    agent_{runs|failed|duration_ms_sum|duration_ms_max}
    http_{requests|rate_limited|body_rejected|bad_json}
    audit_{dispatched|rejected_lines}

No field carries content: latency values are aggregate numbers, token counts
are aggregates, categories are fixed strings.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
_METRICS: "Metrics | None" = None


class Metrics:
    """Thread-safe numeric counters and latency aggregates."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = {}
        self._sums: dict[str, float] = {}
        self._maxs: dict[str, float] = {}
        self._lock = threading.Lock()

    # -- counters ----------------------------------------------------------

    def incr(self, key: str, n: int = 1) -> None:
        if n < 0:
            raise ValueError("n must be >= 0")
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + n

    def record(self, key: str, value: float) -> None:
        """Aggregate a duration (e.g. ``retrieval_latency_ms``): tracks
        sum (for mean) and max; counter with the same name tracks count."""
        with self._lock:
            self._sums[key] = self._sums.get(key, 0.0) + float(value)
            self._maxs[key] = max(self._maxs.get(key, 0.0), float(value))
            self._counters[f"{key}_n"] = self._counters.get(f"{key}_n", 0) + 1

    def mean(self, key: str) -> float | None:
        n = self._counters.get(f"{key}_n", 0)
        if not n:
            return None
        return self._sums[key] / n

    def snapshot(self) -> dict[str, Any]:
        """Plain dict: counters plus derived mean/max per recorded duration.
        Safe to serialize; never contains payload content."""
        with self._lock:
            counters = dict(self._counters)
            sums = dict(self._sums)
            maxs = dict(self._maxs)
        out: dict[str, Any] = {k: v for k, v in counters.items()}
        for key in set(sums) | set(maxs):
            n = counters.get(f"{key}_n", 0)
            if n:
                out[f"{key}_mean"] = round(sums[key] / n, 3)
                out[f"{key}_max"] = round(maxs[key], 3)
            else:
                out[f"{key}_mean"] = None
                out[f"{key}_max"] = None
        return out

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._sums.clear()
            self._maxs.clear()


def get_metrics() -> Metrics:
    """Process-wide singleton (import-safe under concurrency)."""
    global _METRICS
    with _LOCK:
        if _METRICS is None:
            _METRICS = Metrics()
        return _METRICS


class MetricsSink:
    """Append JSONL snapshots of the global metrics to a file.

    Used by deployment tooling (or a periodic task) to persist aggregate
    operational stats. The sink NEVER writes request payloads, addresses,
    task ids or source code — only the numeric snapshot dict.
    """

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._path is not None

    def flush(self, metrics: Metrics | None = None) -> None:
        if not self._path:
            return
        metrics = metrics or get_metrics()
        snap = metrics.snapshot()
        snap["ts"] = time.time()
        line = json.dumps(snap, sort_keys=True)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
