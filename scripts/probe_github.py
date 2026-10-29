"""Probe the three verified GitHub candidates for Stage 10.

  * agentlisa/bench          (LISABench — AgentLISA's benchmark)
  * scarai-xyz/scar-retrieval (SCAR retrieval benchmark)
  * lucianasi/C4Audit        (C4Audit dataset)

Live GitHub API only; nothing assumed. Output appends to
benchmarks/results/dataset_probe.json.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[1] / "benchmarks" / "results"
RESULTS.mkdir(parents=True, exist_ok=True)
PROBE = RESULTS / "dataset_probe.json"

REPOS = [
    "agentlisa/bench",
    "scarai-xyz/scar-retrieval",
    "lucianasi/C4Audit",
    "IlhamQasse/SCAR",
]


def _get(url: str, timeout: float = 40.0) -> dict:
    req = urllib.request.Request(
        url, headers={"User-Agent": "agentsafe-stage10-probe",
                      "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def probe_repo(repo: str) -> dict:
    out: dict = {"repo": repo}
    try:
        info = _get(f"https://api.github.com/repos/{repo}")
        out["description"] = info.get("description")
        out["license"] = (info.get("license") or {}).get("spdx_id")
        out["stars"] = info.get("stargazers_count")
        out["size_kb"] = info.get("size")
        out["default_branch"] = info.get("default_branch")
        out["created"] = info.get("created_at")
        out["updated"] = info.get("updated_at")
        out["archived"] = info.get("archived")
        branch = info.get("default_branch") or "main"
        tree = _get(f"https://api.github.com/repos/{repo}/git/trees/"
                    f"{branch}?recursive=1")
        files = [t["path"] for t in tree.get("tree", [])
                 if t.get("type") == "blob"]
        out["file_count"] = len(files)
        exts: dict[str, int] = {}
        for p in files:
            ext = p.rsplit(".", 1)[-1].lower() if "." in p else "(none)"
            exts[ext] = exts.get(ext, 0) + 1
        out["extensions"] = dict(sorted(exts.items(),
                                        key=lambda kv: -kv[1])[:15])
        out["sample_paths"] = files[:40]
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def main() -> None:
    report = json.loads(PROBE.read_text(encoding="utf-8")) if PROBE.exists() else {}
    for repo in REPOS:
        report[f"github-repo:{repo}"] = probe_repo(repo)
    PROBE.write_text(json.dumps(report, indent=2, ensure_ascii=False,
                               default=str), encoding="utf-8")
    for repo in REPOS:
        r = report[f"github-repo:{repo}"]
        print(json.dumps(r, ensure_ascii=False, default=str)[:900])
        print("-" * 70)


if __name__ == "__main__":
    main()
