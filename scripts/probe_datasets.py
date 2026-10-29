"""Probe candidate public datasets for the Stage 10 evaluation plan.

Stage 10 honesty gate: every candidate dataset must be verified against the
live sources before it is used — existence, splits, row counts, field shape,
license, and per-record structure. Nothing is assumed.

Probes (live HTTP, no caching of fake data):
  * HF dataset search:      https://huggingface.co/api/datasets?search=...
  * HF splits endpoint:     https://datasets-server.huggingface.co/splits?dataset=...
  * HF first rows:          https://datasets-server.huggingface.co/rows?dataset=...

Run with Windows Python (WSL cannot reach HF reliably):
  cmd.exe /c "D:\\360\\git\\agentsafe1\\.venv\\Scripts\\python.exe scripts\\probe_datasets.py"

Output: JSON in benchmarks/results/dataset_probe.json (commit this artifact).
"""

from __future__ import annotations

import json
import sys
import urllib.request
import urllib.parse
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "benchmarks" / "results"
RESULTS.mkdir(parents=True, exist_ok=True)

HF_SEARCH = "https://huggingface.co/api/datasets?search={q}&limit=8"
HF_SPLITS = "https://datasets-server.huggingface.co/splits?dataset={ds}"
HF_ROWS = ("https://datasets-server.huggingface.co/rows"
           "?dataset={ds}&config={cfg}&split={sp}&offset=0&length=2")
HF_INFO = "https://huggingface.co/api/datasets/{ds}"


def _get(url: str, timeout: float = 40.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "agentsafe-stage10-probe"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def probe_dataset(ds: str) -> dict:
    out: dict = {"dataset": ds}
    # splits / row counts
    try:
        sp = _get(HF_SPLITS.format(ds=urllib.parse.quote(ds)))
        configs = []
        for c in sp.get("splits", []):
            configs.append({
                "config": c.get("config"),
                "split": c.get("split"),
                "num_rows": c.get("num_rows"),
            })
        out["splits"] = configs
        if configs:
            c0 = configs[0]
            cfg, split = c0["config"], c0["split"]
            out["default_config"] = cfg
            out["default_split"] = split
            out["total_rows"] = c0["num_rows"]
            try:
                rows = _get(HF_ROWS.format(
                    ds=urllib.parse.quote(ds), cfg=urllib.parse.quote(cfg),
                    sp=urllib.parse.quote(split)))
                sample = [r["row"] for r in rows.get("rows", [])]
                out["fields"] = list(sample[0].keys()) if sample else []
                out["sample"] = sample[:1]
                if sample:
                    r0 = sample[0]
                    out["sample_sizes"] = {k: len(str(v)) for k, v in r0.items()}
            except Exception as exc:
                out["rows_error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        out["splits_error"] = f"{type(exc).__name__}: {exc}"
    # license from the dataset card
    try:
        info = _get(HF_INFO.format(ds=urllib.parse.quote(ds)))
        card = info.get("cardData") or {}
        out["license"] = card.get("license") or card.get("licenses") or None
        out["downloads"] = info.get("downloads")
        out["likes"] = info.get("likes")
        out["tags"] = info.get("tags", [])[:12]
        out["description_head"] = (info.get("description") or "")[:200]
    except Exception as exc:
        out["info_error"] = f"{type(exc).__name__}: {exc}"
    return out


def search(term: str) -> list[dict]:
    try:
        data = _get(HF_SEARCH.format(q=urllib.parse.quote(term)))
        return [{
            "id": d.get("id"),
            "downloads": d.get("downloads"),
            "likes": d.get("likes"),
            "license": (d.get("cardData") or {}).get("license"),
            "lastModified": d.get("lastModified"),
            "description_head": (d.get("description") or "")[:120],
        } for d in data[:8]]
    except Exception as exc:
        return [{"error": f"{type(exc).__name__}: {exc}"}]


def main() -> None:
    report: dict = {}
    for term in ("LISABench", "SCAR smart contract audit", "C4Audit",
                 "code4rena audit findings", "lisabench",
                 "smart contract audit benchmark", "scar solidity",
                 "solidity vulnerability dataset"):
        report[f"search:{term}"] = search(term)
    for ds in ("NyxFoundation/vulnerability-reports",   # SPECA verified earlier
               "GitmateAI/solidity_vulnerability_audit_dataset"):
        report[f"probe:{ds}"] = probe_dataset(ds)
    # GitHub repository search for the other candidates
    gh = "https://api.github.com/search/repositories?q={q}&per_page=5"
    for q in ("LISABench", "SCAR smart contract audit", "C4Audit",
              "smart contract audit benchmark solidity"):
        try:
            req = urllib.request.Request(gh.format(q=urllib.parse.quote(q)),
                                         headers={"User-Agent": "probe",
                                                  "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            report[f"github:{q}"] = [{
                "full_name": it.get("full_name"),
                "stars": it.get("stargazers_count"),
                "license": (it.get("license") or {}).get("spdx_id"),
                "description": (it.get("description") or "")[:150],
            } for it in data.get("items", [])[:5]]
        except Exception as exc:
            report[f"github:{q}"] = [{"error": f"{type(exc).__name__}: {exc}"}]
    out = RESULTS / "dataset_probe.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False,
                              default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str)[:6000])


if __name__ == "__main__":
    main()
