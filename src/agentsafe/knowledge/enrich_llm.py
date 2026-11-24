"""LLM-structured enrichment for real-world vulnerability records.

The bulk of the KB (public Code4rena/Sherlock contest findings, group A) is
imported as verbatim report text. Deterministic markdown extraction fills
`impact`/`remediation`/`vulnerable_code` when a report has those sections, but
it cannot recover `root_cause`, `attack_scenario`, `preconditions`, `tags`,
`subcategory`, or a reliable `category` — the exact intelligence an agent needs
to recognise a vulnerability pattern and reject a false positive. This module
adds that layer with an LLM extraction pass over existing records.

Design contract (matches the rest of the knowledge package):
  * NON-DESTRUCTIVE: only NULL/empty fields are ever filled. A non-null value
    is never overwritten (curated / reproduced rows are skipped entirely).
  * HONEST: the model must return JSON; anything it cannot support with the
    report text is null. Category is snapped to the KB vocabulary; an
    out-of-vocabulary label becomes null rather than a new taxonomy. Derived
    fields are recorded in metadata under ``llm_enrichment`` with the model
    name, and the row's verification_status becomes ``llm-enriched`` (never
    ``confirmed``/``reproduced``).
  * IDEMPOTENT: a row already carrying ``metadata.llm_enrichment`` is never
    re-sent to the model, so a re-run is a no-op and costs no calls.
  * BOUNDED: every call reads at most ``TXT_CAP`` characters of report text;
    field lengths and list sizes are capped.
  * Chunk children (``metadata.parent_external_id`` set) inherit their
    parent's structured intelligence (fill-nulls only), so every retrievable
    chunk carries the same root cause and attack scenario as its parent.

The LLM call itself is injected as ``llm(messages) -> str`` so the pass is
unit-testable without a provider and so a runner can supply the production
provider client (``ProviderLLMClient``).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agentsafe.knowledge.enrich import (
    _CATEGORY_ORDER,
    GROUP_A_SOURCES,
    VERIFIED_STATUSES,
)

logger = logging.getLogger("agentSAFE.knowledge.enrich_llm")

TXT_CAP = 12_000                 # report chars fed to the model per record
MAX_PRECONDITIONS = 6
MAX_TAGS = 8
VS_LLM_ENRICHED = "llm-enriched"
LLM_ENRICH_TAG = "llm_enrichment"

# Fields copied from an enriched parent onto its chunk children.
_PROPAGATED = ("root_cause", "attack_scenario", "exploit_sequence",
               "preconditions", "subcategory", "category", "swc_id", "tags",
               "confidence", "verification_status")

_CATEGORY_SET = set(_CATEGORY_ORDER)
_SYSTEM_PROMPT = (
    "You are a senior smart-contract vulnerability researcher. Extract "
    "structured intelligence from ONE public audit finding so a detection "
    "agent can recognise the same class of bug. Output ONLY the JSON object: "
    "no analysis, no explanation, no markdown fences, nothing before or after "
    "the object. Base every field strictly on the report text; when the text "
    "does not support a field, use null (or an empty list). Never invent code, "
    "values, or exploits that are not described."
)


@dataclass
class ExtractedIntel:
    root_cause: str | None = None
    attack_scenario: str | None = None
    preconditions: list[str] = field(default_factory=list)
    impact: str | None = None
    remediation: str | None = None
    category: str | None = None
    subcategory: str | None = None
    swc_id: str | None = None
    tags: list[str] = field(default_factory=list)
    confidence: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_cause": self.root_cause,
            "attack_scenario": self.attack_scenario,
            "preconditions": self.preconditions,
            "impact": self.impact,
            "remediation": self.remediation,
            "category": self.category,
            "subcategory": self.subcategory,
            "swc_id": self.swc_id,
            "tags": self.tags,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# prompt + parse
# ---------------------------------------------------------------------------
def build_messages(title: str, description: str) -> list[dict[str, str]]:
    categories = ", ".join(_CATEGORY_ORDER)
    body = (description or "")[:TXT_CAP]
    user = (
        f"TITLE: {title or '(none)'}\n\n"
        f"REPORT TEXT:\n{body}\n\n"
        "Return a JSON object with EXACTLY these keys:\n"
        '  "root_cause": the specific code-level defect in one or two '
        'sentences (what the code does wrong), or null.\n'
        '  "attack_scenario": an ordered, concrete exploit walk-through '
        '(attacker steps -> vulnerable path -> effect), or null.\n'
        '  "preconditions": array of the conditions an attacker or the '
        'system state must satisfy for the bug to be exploitable.\n'
        f'  "impact": the concrete consequence (loss, insolvency, DoS, ...), '
        'or null.\n'
        '  "remediation": the fix the report/recommendation states, or null.\n'
        f'  "category": ONE of [{categories}] or null if none fits.\n'
        '  "subcategory": a short finer label (e.g. "first-depositor-'
        'inflation", "missing-freshness-check"), or null.\n'
        '  "swc_id": a SWC identifier like "SWC-107" ONLY if clearly '
        'applicable, else null.\n'
        '  "tags": up to 8 short lowercase keywords (functions, tokens, '
        'mechanisms).\n'
        '  "confidence": a number in [0,1] reflecting how well the text '
        'supports the extraction.\n'
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def _clean_str(v: Any, cap: int) -> str | None:
    if not isinstance(v, str):
        return None
    s = " ".join(v.split()).strip()
    if not s or s.lower() in {"null", "none", "n/a", "na", "unknown"}:
        return None
    return s[:cap]


def _clean_list(v: Any, cap_items: int, cap_item: int) -> list[str]:
    if isinstance(v, str):
        v = [x for x in v.replace("\n", ";").split(";")]
    if not isinstance(v, (list, tuple)):
        return []
    out: list[str] = []
    for item in v:
        s = _clean_str(item, cap_item)
        if s and s.lower() not in {x.lower() for x in out}:
            out.append(s)
        if len(out) >= cap_items:
            break
    return out


def parse_extracted(content: str) -> ExtractedIntel:
    """Parse the model's JSON into an ExtractedIntel, defensively.

    Raises ValueError when no JSON object can be recovered (the caller counts
    it as a failure and never writes partial garbage)."""
    data = _loads_loose(content)
    if not isinstance(data, dict):
        raise ValueError("model response is not a JSON object")
    cat = _clean_str(data.get("category"), 64)
    cat = cat.lower() if cat else None
    if cat not in _CATEGORY_SET:
        cat = None
    swc = _clean_str(data.get("swc_id"), 16)
    if swc and not swc.upper().startswith("SWC-"):
        swc = None
    conf = data.get("confidence")
    try:
        conf = float(conf) if conf is not None else None
    except (TypeError, ValueError):
        conf = None
    if conf is not None:
        conf = min(1.0, max(0.0, conf))
    return ExtractedIntel(
        root_cause=_clean_str(data.get("root_cause"), 1200),
        attack_scenario=_clean_str(data.get("attack_scenario"), 1600),
        preconditions=_clean_list(data.get("preconditions"),
                                  MAX_PRECONDITIONS, 240),
        impact=_clean_str(data.get("impact"), 1200),
        remediation=_clean_str(data.get("remediation"), 1200),
        category=cat,
        subcategory=_clean_str(data.get("subcategory"), 120),
        swc_id=swc.upper() if swc else None,
        tags=[t.lower() for t in _clean_list(data.get("tags"), MAX_TAGS, 40)],
        confidence=conf,
    )


def _contains_json(text: str) -> bool:
    try:
        from agentsafe.llm.repair import extract_balanced
        return extract_balanced(text) is not None
    except Exception:  # noqa: BLE001
        return "{" in text and "}" in text


def _loads_loose(text: str) -> Any:
    """Parse JSON that may be wrapped in ```json fences or prose."""
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    try:
        from agentsafe.llm.repair import extract_balanced
        balanced = extract_balanced(text)
        if balanced:
            return json.loads(balanced)
    except Exception as exc:  # noqa: BLE001 - best-effort loose parse
        logger.debug("loose JSON extraction failed: %s", exc)
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start:end + 1])
        except (ValueError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# non-destructive update planning
# ---------------------------------------------------------------------------
def _is_empty(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, str):
        return not v.strip()
    if isinstance(v, (list, dict)):
        return len(v) == 0
    return False


def plan_update(row: dict[str, Any], intel: ExtractedIntel, *,
                model: str = "llm", now: str | None = None) -> dict[str, Any]:
    """Return the column -> value UPDATE for one row, filling NULLs only.

    Returns {} when nothing new can be added. Values for jsonb columns are
    pre-serialized JSON strings."""
    sets: dict[str, Any] = {}
    for col, val in (("root_cause", intel.root_cause),
                     ("attack_scenario", intel.attack_scenario),
                     ("impact", intel.impact),
                     ("remediation", intel.remediation)):
        if _is_empty(row.get(col)) and val:
            sets[col] = val
    if intel.attack_scenario and _is_empty(row.get("exploit_sequence")):
        sets["exploit_sequence"] = intel.attack_scenario
    if _is_empty(row.get("category")) and intel.category:
        sets["category"] = intel.category
    if _is_empty(row.get("preconditions")) and intel.preconditions:
        sets["preconditions"] = json.dumps(intel.preconditions)
    if _is_empty(row.get("subcategory")) and intel.subcategory:
        sets["subcategory"] = intel.subcategory
    if _is_empty(row.get("swc_id")) and intel.swc_id:
        sets["swc_id"] = intel.swc_id
    if _is_empty(row.get("tags")) and intel.tags:
        sets["tags"] = json.dumps(intel.tags)
    if row.get("confidence") is None and intel.confidence is not None:
        sets["confidence"] = intel.confidence
    if not sets:
        return {}
    sets["kb_group"] = "A"
    sets["verification_status"] = VS_LLM_ENRICHED
    md = dict(row.get("metadata") or {}) if isinstance(row.get("metadata"), dict) \
        else {}
    md[LLM_ENRICH_TAG] = {
        "method": "llm-structured-extraction",
        "model": model,
        "derived_fields": sorted(k for k in sets
                                 if k not in ("kb_group", "verification_status")),
        "extracted_at": now or datetime.now(UTC).isoformat(),
    }
    sets["metadata"] = json.dumps(md)
    return sets


# ---------------------------------------------------------------------------
# store pass
# ---------------------------------------------------------------------------
@dataclass
class EnrichLLMSummary:
    scanned: int = 0
    enriched: int = 0
    unchanged: int = 0
    failed: int = 0
    calls: int = 0
    children_updated: int = 0
    skipped_verified: int = 0
    fields_written: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned, "enriched": self.enriched,
            "unchanged": self.unchanged, "failed": self.failed,
            "calls": self.calls, "children_updated": self.children_updated,
            "skipped_verified": self.skipped_verified,
            "fields_written": dict(self.fields_written),
            "errors": self.errors[:20],
        }


_FETCH_SQL = """
    SELECT id, source_id, external_record_id, title, description, category,
           root_cause, attack_scenario, exploit_sequence, impact, remediation,
           preconditions, subcategory, swc_id, tags, confidence, metadata,
           verification_status
    FROM vulnerability_knowledge
    WHERE source_id = ANY(%s)
      AND (__PARENTS__)
      AND NOT (metadata ? %s)
      AND (verification_status IS NULL OR NOT (verification_status = ANY(%s)))
    ORDER BY id
    LIMIT %s
"""


def enrich_group_a_llm(
    store: Any,
    *,
    llm: Callable[[list[dict[str, str]]], str],
    source_ids: tuple[str, ...] = GROUP_A_SOURCES,
    limit: int = 200,
    only_parents: bool = True,
    propagate: bool = True,
    model: str = "llm",
    txt_cap: int = TXT_CAP,
    concurrency: int = 1,
    progress: Callable[[int, int], None] | None = None,
) -> EnrichLLMSummary:
    """Enrich up to ``limit`` group-A records with the LLM, then propagate the
    derived fields to their chunk children (fill-nulls only).

    ``concurrency`` runs that many extraction calls at once (each call is an
    independent HTTP request; the provider client already rotates providers and
    the run stays under provider RPM limits). The DB is never touched during
    phase 1, so concurrency introduces no locking or transaction risk."""
    summary = EnrichLLMSummary()
    verified = sorted(VERIFIED_STATUSES)
    parents_clause = ("metadata->>'parent_external_id' IS NULL"
                      if only_parents else "TRUE")
    with store._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                _FETCH_SQL.replace("__PARENTS__", parents_clause),
                (list(source_ids), LLM_ENRICH_TAG, verified, int(limit)),
            )
            rows = list(cur.fetchall())
    # Phase 1 — LLM extraction only (no DB connection held during the slow
    # remote calls; Neon kills idle-in-transaction sessions). Plans are
    # collected in memory. Extraction calls are independent, so they may run
    # concurrently.
    eligible: list[dict[str, Any]] = []
    for row in rows:
        summary.scanned += 1
        if row.get("verification_status") in VERIFIED_STATUSES:
            summary.skipped_verified += 1
        else:
            eligible.append(row)

    def _extract(row: dict[str, Any]) -> ExtractedIntel:
        text = row.get("description") or ""
        if txt_cap and len(text) > txt_cap:
            text = text[:txt_cap]
        summary.calls += 1
        return parse_extracted(llm(build_messages(row.get("title") or "", text)))

    def _tick(done: int) -> None:
        if progress is not None:
            try:
                progress(done, len(eligible))
            except Exception as exc:  # noqa: BLE001 - progress never breaks
                logger.debug("progress callback failed: %s", exc)

    results: list[tuple[dict[str, Any], ExtractedIntel | None,
                        Exception | None]] = []
    if concurrency > 1 and len(eligible) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(
                max_workers=min(concurrency, len(eligible))) as pool:
            futures = {pool.submit(_extract, row): row for row in eligible}
            for fut in as_completed(futures):
                row = futures[fut]
                try:
                    results.append((row, fut.result(), None))
                except Exception as exc:  # noqa: BLE001 - per-row failure
                    results.append((row, None, exc))
                _tick(len(results))
    else:
        for row in eligible:
            try:
                results.append((row, _extract(row), None))
            except Exception as exc:  # noqa: BLE001 - per-row failure
                results.append((row, None, exc))
            _tick(len(results))

    plans: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for row, intel, exc in results:
        if exc is not None or intel is None:
            summary.failed += 1
            summary.errors.append(f"row {row.get('id')}: {exc}")
            continue
        try:
            sets = plan_update(row, intel, model=model)
        except Exception as exc2:  # noqa: BLE001
            summary.failed += 1
            summary.errors.append(f"row {row.get('id')}: plan {exc2}")
            continue
        if not sets:
            summary.unchanged += 1
            continue
        plans.append((row, sets))
        summary.enriched += 1
        for k in sets:
            summary.fields_written[k] = summary.fields_written.get(k, 0) + 1

    # Phase 2 — batch-write the plans over a few fresh connections (no LLM
    # between statements, so no idle-in-transaction risk). Rows in a batch carry
    # different column sets, so each UPDATE is built per row; the win is one
    # connection per batch instead of one per row.
    for i in range(0, len(plans), 25):
        batch = plans[i:i + 25]
        try:
            with store._connect() as conn:
                with conn.cursor() as cur:
                    for row, sets in batch:
                        cols = ", ".join(f"{k} = %s" for k in sets)  # keys are a fixed whitelist
                        cur.execute(
                            f"UPDATE vulnerability_knowledge SET {cols}, "  # noqa: S608
                            "updated_at = now() WHERE id = %s",
                            (*sets.values(), row["id"]),
                        )
        except Exception as exc:  # noqa: BLE001 - rerun finishes (idempotent)
            summary.failed += len(batch)
            summary.enriched -= len(batch)
            summary.errors.append(f"batch {i // 25}: write {exc}")

    # Optional per-parent propagation (kept for callers/tests); the runner uses
    # the faster set-based sweep in maintenance.propagate_parent_intelligence.
    if propagate:
        for row, sets in plans:
            if row.get("external_record_id"):
                try:
                    summary.children_updated += _propagate_to_children(
                        store, str(row.get("source_id") or ""),
                        row["external_record_id"], sets)
                except Exception as exc:  # noqa: BLE001 - additive
                    summary.errors.append(
                        f"row {row.get('id')}: propagate {exc}")
    from agentsafe.metrics import get_metrics
    get_metrics().incr("enrich_llm_enriched", summary.enriched)
    return summary


def _update_row(store: Any, row_id: int, sets: dict[str, Any]) -> None:
    cols = ", ".join(f"{k} = %s" for k in sets)  # keys are a fixed whitelist
    with store._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                # keys are a fixed whitelist; values are bound parameters
                f"UPDATE vulnerability_knowledge SET {cols}, updated_at = now() "  # noqa: S608
                "WHERE id = %s",
                (*sets.values(), row_id),
            )


def _propagate_to_children(store: Any, source_id: str, parent_ext_id: str,
                           parent_sets: dict[str, Any]) -> int:
    """Copy shared intelligence from an enriched parent to its chunk children,
    filling NULL/empty child fields only. Children are found by the
    ``metadata.parent_external_id`` marker written at import time."""
    shared = {k: v for k, v in parent_sets.items() if k in _PROPAGATED}
    if not source_id or not shared:
        return 0
    updated = 0
    with store._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, root_cause, attack_scenario, exploit_sequence, "
                "preconditions, subcategory, category, swc_id, tags, confidence, "
                "verification_status, metadata "
                "FROM vulnerability_knowledge "
                "WHERE source_id = %s AND metadata->>'parent_external_id' = %s",
                (source_id, parent_ext_id),
            )
            children = list(cur.fetchall())
            for ch in children:
                sets: dict[str, Any] = {}
                for k, v in shared.items():
                    if k in ("preconditions", "tags"):
                        if _is_empty(ch.get(k)):
                            sets[k] = v
                    elif _is_empty(ch.get(k)):
                        sets[k] = v
                if not sets:
                    continue
                md = dict(ch.get("metadata") or {}) \
                    if isinstance(ch.get("metadata"), dict) else {}
                md[LLM_ENRICH_TAG] = {
                    "method": "llm-structured-extraction",
                    "propagated_from": parent_ext_id,
                }
                sets["metadata"] = json.dumps(md)
                cols = ", ".join(f"{k} = %s" for k in sets)  # keys are a fixed whitelist
                cur.execute(
                    # keys are a fixed whitelist; values are bound
                    f"UPDATE vulnerability_knowledge SET {cols}, "  # noqa: S608
                    "updated_at = now() WHERE id = %s",
                    (*sets.values(), ch["id"]),
                )
                updated += 1
    return updated


# ---------------------------------------------------------------------------
# production provider client
# ---------------------------------------------------------------------------
class ProviderLLMClient:
    """Minimal OpenAI-compatible chat client that rotates configured providers.

    Reads ``LLM_PROVIDERS_JSON`` (the same config the audit router uses). On a
    transient failure (429 / 5xx / network) it rotates to the next provider;
    after ``passes`` full rotations it raises. Returns the raw message content
    string (the caller parses it), never a fabricated answer."""

    def __init__(self, providers: list[dict[str, Any]], *,
                 timeout: float = 90.0, passes: int = 2,
                 max_tokens: int = 2048,
                 extra_payload: dict[str, Any] | None = None) -> None:
        self.providers = providers
        self.timeout = timeout
        self.passes = max(1, passes)
        self.max_tokens = max_tokens
        # Merged into every request body. Used to disable chain-of-thought on
        # providers that honour it (``enable_thinking: false``): identical JSON,
        # ~5x lower latency, so a large enrichment pass is practical. A provider
        # that rejects the field is simply skipped by the rotation.
        self.extra_payload = dict(extra_payload or {})
        self._last_good: str | None = None
        self._skip: set[str] = set()   # providers that returned no usable JSON

    def _order(self) -> list[dict[str, Any]]:
        """Last-good provider first; providers that returned no usable answer
        are dropped for the rest of the run (so a reasoning-only model that
        never emits JSON is paid for at most once)."""
        active = [p for p in self.providers
                  if p.get("name") not in self._skip]
        if not active:                       # never strand the client
            active = list(self.providers)
        active.sort(key=lambda p: p.get("name") != self._last_good)
        return active

    def __call__(self, messages: list[dict[str, str]]) -> str:
        import time
        import urllib.error
        import urllib.request

        last: Exception | None = None
        for attempt in range(self.passes):
            for p in self._order():
                payload = {
                    "model": p["model"],
                    "messages": messages,
                    "temperature": 0,
                    "max_tokens": self.max_tokens,
                }
                payload.update(self.extra_payload)
                body = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(  # noqa: S310 - https base_url from config
                    p["base_url"].rstrip("/") + "/chat/completions", data=body,
                    headers={"Authorization": f"Bearer {p['api_key']}",
                             "Content-Type": "application/json",
                             "Accept": "application/json"},
                    method="POST")
                try:
                    with urllib.request.urlopen(  # noqa: S310 - https provider URL
                            req, timeout=self.timeout) as r:
                        data = json.loads(r.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    last = exc
                    name = str(p.get("name"))
                    # 429/5xx are transient (keep the provider). Bad key/model/
                    # path (400/401/403/404/405) is permanent for this run.
                    if exc.code not in (429, 500, 502, 503, 504):
                        self._skip.add(name)
                    continue
                except Exception as exc:  # noqa: BLE001 - rotate on network
                    last = exc
                    continue
                name = str(p.get("name"))
                msg = (data.get("choices") or [{}])[0].get("message") or {}
                content = (msg.get("content") or "").strip()
                if not content:
                    # Some reasoning models emit only a reasoning trace; use it
                    # ONLY if it actually contains a JSON object.
                    trace = (msg.get("reasoning_content")
                             or msg.get("reasoning") or "")
                    if trace and _contains_json(trace):
                        content = trace.strip()
                if content:
                    self._last_good = name
                    return content
                # No usable answer: stop paying this provider for the run.
                self._skip.add(name)
                last = RuntimeError(f"provider {name} returned no JSON")
            time.sleep(1.0 * (attempt + 1))
        raise RuntimeError(f"all LLM providers failed: {last}")


def providers_from_env(config: Any = None) -> list[dict[str, Any]]:
    """Build the provider list from settings/LLM_PROVIDERS_JSON (keys kept
    in-process only; never logged)."""
    import os

    raw = ""
    if config is not None:
        raw = str(getattr(config, "LLM_PROVIDERS_JSON", "") or "")
    if not raw:
        raw = os.environ.get("LLM_PROVIDERS_JSON", "")
    if not raw.strip():
        return []
    data = json.loads(raw)
    if not isinstance(data, list):
        return []
    out = []
    for p in data:
        if isinstance(p, dict) and p.get("api_key") and p.get("base_url"):
            out.append(p)
    # Preferred provider first, then declaration order.
    out.sort(key=lambda p: (not p.get("preferred"),))
    return out
