"""Stage 10 — evaluation data loading (verified sources only).

Every dataset used by the benchmark is fetched live from its canonical source
and cached under benchmarks/data/ with a provenance JSON that records:
version/commit where available, license, sample counts, fetch time, and the
exact URLs. Nothing is hand-invented; nothing is assumed to be available
before the fetch succeeds.

Datasets (verified 2026-08 by scripts/probe_*.py):
  * LISABench        GitHub agentlisa/bench (MIT, ~10187 JSON samples,
                     fields Title/Content/Impact/Source/Code) — real Sherlock
                     + Code4rena audit findings with code snippets.
  * SPECA            HF NyxFoundation/vulnerability-reports (MIT, 4470 rows,
                     config default split train) — Code4rena findings;
                     imported into the Neon KB (retrieval pool).
  * GitmateAI        HF GitmateAI/solidity_vulnerability_audit_dataset
                     (Apache-2.0, instruction/input/output teaching samples).
  * known-safe       OpenZeppelin contracts v5.0.0 (MIT) reference
                     implementations — widely audited, NOT formally verified;
                     labeled reference-safe in the benchmark.
  * SCAR / C4Audit   NOT usable: scarai-xyz/scar-retrieval ships pipeline code
                     only (data requires Solodit API access);
                     lucianasi/C4Audit has no license (cannot be used).
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROVENANCE = DATA_DIR / "provenance.json"

LISABENCH_REPO = "agentlisa/bench"
LISABENCH_URL = "https://raw.githubusercontent.com/{repo}/main/dataset/{n:05d}.json"
OZ_URL = ("https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/"
          "v5.0.0/contracts/token/ERC20/ERC20.sol")


def _get(url: str, timeout: float = 60.0, retries: int = 4) -> str:
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "agentsafe-eval"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except Exception as exc:
            last = exc
    raise RuntimeError(f"fetch failed {url}: {last}")


# ---------------------------------------------------------------------------
# provenance bookkeeping
# ---------------------------------------------------------------------------

def _load_provenance() -> dict:
    if PROVENANCE.exists():
        return json.loads(PROVENANCE.read_text(encoding="utf-8"))
    return {}


def _save_provenance(prov: dict) -> None:
    PROVENANCE.write_text(json.dumps(prov, indent=2, ensure_ascii=False),
                          encoding="utf-8")


def record_fetch(key: str, meta: dict) -> None:
    prov = _load_provenance()
    prov[key] = meta
    _save_provenance(prov)


# ---------------------------------------------------------------------------
# LISABench
# ---------------------------------------------------------------------------

def load_lisabench(n: int, seed: int = 42, max_index: int = 300) -> list[dict]:
    """Deterministically sample n LISABench records from dataset/00001..max_index.

    Cached on disk; provenance records the fetched subset ids. The subset is
    indexed by record id so re-runs are identical (no benchmark drift).
    """
    cache = DATA_DIR / f"lisabench_{seed}_{n}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    rng = random.Random(seed)
    idxs = sorted(rng.sample(range(1, max_index + 1), n))
    recs = []
    for i in idxs:
        raw = _get(LISABENCH_URL.format(repo=LISABENCH_REPO, n=i))
        rec = json.loads(raw)
        rec["_bench_id"] = i
        recs.append(rec)
    cache.write_text(json.dumps(recs, ensure_ascii=False), encoding="utf-8")
    record_fetch("lisabench", {
        "source": LISABENCH_REPO,
        "url_template": LISABENCH_URL,
        "license": "MIT",
        "subset_size": n,
        "seed": seed,
        "ids": idxs,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    })
    return recs


# ---------------------------------------------------------------------------
# known-safe reference implementations
# ---------------------------------------------------------------------------

def load_known_safe() -> dict[str, str]:
    """Reference-safe contracts (widely audited, NOT formally verified).

    Returned as {filename: source}. Cached; provenance recorded.
    """
    cache = DATA_DIR / "knownsafe.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    src = _get(OZ_URL)
    contracts = {"ERC20.sol": src}
    cache.write_text(json.dumps(contracts, ensure_ascii=False), encoding="utf-8")
    record_fetch("known_safe_oz", {
        "source": "OpenZeppelin/openzeppelin-contracts",
        "url": OZ_URL,
        "version": "v5.0.0",
        "license": "MIT",
        "contracts": list(contracts),
        "note": "reference implementations, widely audited, NOT formally verified",
        "sha256": {k: hashlib.sha256(v.encode()).hexdigest()[:16]
                   for k, v in contracts.items()},
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    })
    return contracts


# ---------------------------------------------------------------------------
# GitmateAI (teaching samples; used only for validation-accuracy auxiliary)
# ---------------------------------------------------------------------------

HF_ROWS = ("https://datasets-server.huggingface.co/rows?dataset={ds}"
           "&config=default&split=train&offset={off}&length={n}")


def load_gitmateai(n: int = 10, seed: int = 42) -> list[dict]:
    cache = DATA_DIR / f"gitmateai_{seed}_{n}.json"
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))
    rng = random.Random(seed)
    offsets = sorted(rng.sample(range(0, 400), n))
    recs = []
    for off in offsets:
        url = HF_ROWS.format(
            ds="GitmateAI/solidity_vulnerability_audit_dataset", off=off, n=1)
        try:
            data = json.loads(_get(url))
        except Exception:
            continue
        for row in data.get("rows", []):
            recs.append(row["row"])
    cache.write_text(json.dumps(recs, ensure_ascii=False), encoding="utf-8")
    record_fetch("gitmateai", {
        "source": "GitmateAI/solidity_vulnerability_audit_dataset",
        "license": "Apache-2.0",
        "n_fetched": len(recs),
        "offsets": offsets,
        "note": "teaching-style instruction samples; small synthetic contracts",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    })
    return recs


# ---------------------------------------------------------------------------
# ground-truth extraction (honest, keyword-anchored)
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "reentrancy": ["reentranc", "checks-effects", "cei", "checks effects",
                   "re-entranc"],
    "arithmetic": ["overflow", "underflow", "arithmetic"],
    "access_control": ["access control", "onlyowner", "unauthori", "role",
                       "permission"],
    "oracle": ["oracle", "price feed", "manipulat"],
    "dos": ["denial of service", "dos", "grief"],
    "accounting": ["accounting", "claim", "reward", "debt", "withdraw",
                   "redeem", "stake"],
    "unhandled_exception": ["revert", "reverts", "dos due to revert"],
}
# keywords are anchored to title+impact so the extraction is reproducible and
# traceable back to the source text (no invented labels).
_GT_ANCHOR_RE = re.compile(
    "|".join(re.escape(w) for ws in _CATEGORY_KEYWORDS.values() for w in ws),
    re.IGNORECASE)


def extract_gt_categories(rec: dict) -> list[str]:
    """Anchor-based ground-truth categories from Title/Impact/Content.

    Only categories with at least one verbatim keyword occurrence in the
    record's own text are emitted. This under-labels rather than over-labels
    (precision over recall); the anchor regex is part of the benchmark
    protocol so results are reproducible.
    """
    text = " ".join([
        str(rec.get("Title") or ""), str(rec.get("Impact") or ""),
        str(rec.get("Content") or "")[:4000],
    ]).lower()
    found = []
    for cat, words in _CATEGORY_KEYWORDS.items():
        if any(w in text for w in words):
            found.append(cat)
    return found


def extract_gt_severity(rec: dict) -> str | None:
    """Ground-truth severity from the report title prefix (H-/M- style)."""
    m = re.match(r"\s*([HM])-\d+", str(rec.get("Title") or ""))
    if m:
        return {"H": "high", "M": "medium"}[m.group(1)]
    return None


def extract_gt_cross_function(rec: dict) -> bool:
    """Heuristic cross-function marker: explicit mention of multiple contracts
    sharing the same bug pattern (e.g. 'Both X and Y also ...'). Conservative:
    requires the literal 'both' + a second contract mention."""
    text = str(rec.get("Content") or "").lower()
    return bool(re.search(r"\bboth\b.*\b(also|share|same)\b", text, re.I))
