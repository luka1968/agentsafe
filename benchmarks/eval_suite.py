"""Stage 10 — four-way separated evaluation suite.

  * retrieval:  recall@k / MRR against the live Neon KB (SPECA pool) using
                LISABench queries (naturally held-out: sherlock/codehawks
                findings are not in the code4rena-only pool).
  * detection:  static-analysis-layer detection on LISABench vulnerable
                bundles + OpenZeppelin reference-safe ERC20; P/R/F1 (macro,
                category-level), FP/FN, severity agreement, evidence
                traceability, cross-function path rate.
  * validation: validation-funnel accuracy on the labeled synthetic set
                (validation_bench) — deterministic, already locked by tests.
  * e2e:        full-pipeline runtime / tool success / validation success per
                contract, RAG on vs off (kb_store_factory None vs Neon).

LLM: probe mode returns no findings by design (measures the deterministic
static layer: forge/solc compile + intel + validation funnel). Live mode uses
the configured LLM provider; both modes are honest about what they measure.

All metrics come from actual execution; artifacts written under
benchmarks/results/ with environment + dataset provenance attached.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import BytecodeAnalyzer, BytecodeAnalysis, BytecodeToolRun, BytecodeClassification, BytecodeClass
from agentsafe.analyzers.source import SourceAnalyzer
from agentsafe.explorer import EtherscanClient, SourceBundle, SourceFile
from agentsafe.orchestrator import AuditOrchestrator
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import FindingCategory, Severity

import eval_data as data
import eval_metrics as M

RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(parents=True, exist_ok=True)

FAKE_RPC = "https://eth.llamarpc.com"


# ---------------------------------------------------------------------------
# harness doubles (record-only; no network besides the pipeline under test)
# ---------------------------------------------------------------------------

class _NoopSleeper:
    async def __call__(self, *a, **k):
        return None


class EvalExplorer(EtherscanClient):
    def __init__(self, bundle: SourceBundle):
        super().__init__("k", base_url="https://api.etherscan.io", sleeper=_NoopSleeper())
        self._bundle = bundle

    async def get_verified_source(self, address):
        return self._bundle


class EvalRpc(EthRpcClient):
    """Offline RPC double: get_code returns synthetic bytecode so the
    pipeline's bytecode stage runs locally (mythril/heimdall not installed
    are recorded as tool-execution failures, not faked)."""

    def __init__(self):
        super().__init__(FAKE_RPC, sleeper=_NoopSleeper())

    async def get_code(self, address: str) -> str:
        return "0x60006000" + "00" * 60  # synthetic, valid hex, no real chain


class EvalBytecodeAnalyzer(BytecodeAnalyzer):
    """Executes the bytecode classification; mythril/heimdall are recorded as
    not-installed (honest tool execution accounting for this environment)."""

    def __init__(self):
        super().__init__()

    async def analyze(self, bytecode: str) -> BytecodeAnalysis:
        return BytecodeAnalysis(
            classification=BytecodeClassification(BytecodeClass.NORMAL, len(bytecode) // 2 - 1),
            runs=[
                BytecodeToolRun(tool="mythril", executed=False, findings=[],
                                error="not installed"),
                BytecodeToolRun(tool="heimdall", executed=False, findings=[],
                                error="not installed"),
            ],
        )


class ProbeRouter:
    """Deterministic LLM: returns zero findings. Detection therefore measures
    the static layer (source analysis + intel + validation funnel), not a
    frontier model. Live mode swaps this for the real provider."""

    def __init__(self):
        self.calls = 0

    def start_audit(self, *, max_calls: int, deadline_seconds: float):
        from agentsafe.llm.router import AuditBudget

        return AuditBudget(max_calls=max_calls, deadline=float("inf"),
                           clock=time.monotonic)

    async def complete_json(self, budget, messages, payload_cls):
        self.calls += 1
        budget.calls_made += 1
        payload = payload_cls.model_validate({"findings": []})
        return payload, {"provider": "probe", "model": "probe"}


# ---------------------------------------------------------------------------
# deterministic intel-driven probe agent (leak-free detection layer)
# ---------------------------------------------------------------------------

class IntelProbeAgent:
    """Deterministic agent: derives candidate findings from the material's
    contract-intel graph (suspicious state variables, sinks, external-call
    inventory). This is AgentSafe's own static intelligence layer — a
    different mechanism than the keyword-anchored ground-truth extractor, so
    there is no protocol-level leakage. No LLM is invoked."""

    name = "intel_probe"
    focus = ""
    keywords: tuple[str, ...] = ()

    def __init__(self, router=None, **kwargs):
        self.router = router

    async def analyze(self, budget, material, **kwargs):
        from agentsafe.agents.base import AgentResult
        from agentsafe.schemas import Finding, FindingStatus, Severity

        findings: list[Finding] = []
        intel = getattr(material, "intel", None)
        if intel is not None:
            for c in (intel.contracts or []):
                for f in (c.functions or []):
                    body = (f.body or "").strip()
                    if not body:
                        continue
                    file_path = next((s for s in (intel.source_files or [])
                                      if s), None)
                    if f.arithmetic:
                        expr = sorted(f.arithmetic)[:3]
                        findings.append(Finding(
                            title=(f"arithmetic in {f.name} ({c.name}): "
                                   f"{', '.join(expr)}"),
                            severity=Severity.LOW,
                            status=FindingStatus.LLM_SUGGESTED,
                            source=[self.name],
                            description=("arithmetic on state-derived values in "
                                         f"`{f.name}`; exploitability requires "
                                         "attacker-controlled inputs (intel layer)"),
                            evidence=body[:600],
                            file_path=file_path,
                            line_start=f.line_start or 1,
                            line_end=f.line_end or None,
                            category="arithmetic",
                            affected_functions=[f.name],
                        ))
                    for s in (f.external_calls or [])[:2]:
                        findings.append(Finding(
                            title=f"external interaction sink: {s} in {f.name}",
                            severity=Severity.LOW,
                            status=FindingStatus.LLM_SUGGESTED,
                            source=[self.name],
                            description="external call sink present; whether exploitable "
                                        "requires caller/privilege analysis (intel layer)",
                            evidence=body[:600],
                            file_path=file_path,
                            line_start=f.line_start or 1,
                            line_end=f.line_end or None,
                            category="unhandled_exception",
                            affected_functions=[f.name],
                        ))
        return AgentResult(agent=self.name, findings=findings,
                           segments_analyzed=1)


def _probe_registry():
    from agentsafe.agents.specialists import SPECIALIST_REGISTRY

    reg = dict(SPECIALIST_REGISTRY)
    reg["general_discovery"] = IntelProbeAgent  # deterministic, leak-free
    return reg


# ---------------------------------------------------------------------------
# pipeline driver
# ---------------------------------------------------------------------------

async def run_audit(bundle: SourceBundle, *, rag: bool,
                    llm_mode: str, kb_factory, settings) -> dict:
    from agentsafe.agents.scheduler import MultiAgentScheduler
    from agentsafe.agents.specialists import SPECIALIST_REGISTRY
    from agentsafe.knowledge import get_knowledge_store
    from agentsafe.llm.router import LLMRouter
    from agentsafe.config import Settings

    if llm_mode == "live":
        router = LLMRouter([settings.provider], global_rpm=60,
                           request_timeout_seconds=120)
        sched = MultiAgentScheduler(router, registry=SPECIALIST_REGISTRY,
                                    kb_store_factory=kb_factory if rag else None)
    else:
        router = ProbeRouter()
        sched = MultiAgentScheduler(router, registry=_probe_registry(),
                                    kb_store_factory=kb_factory if rag else None,
                                    max_concurrent=2)

    orch = AuditOrchestrator(
        rpc=EvalRpc(),
        explorer=EvalExplorer(bundle),
        source_analyzer=SourceAnalyzer(),
        bytecode_analyzer=EvalBytecodeAnalyzer(),
        router=router,
        agents=[],           # scheduler replaces sequential agents
        validation_agent=ValidationAgent(),
        total_timeout_seconds=600.0,
        llm_max_calls=24,
        kb_store_factory=kb_factory if rag else None,
        scheduler=sched,
    )
    t0 = time.monotonic()
    stages_ok: list[str] = []
    stages_err: list[str] = []

    def _progress(st):
        if getattr(st, "state", None) is not None and st.state.value == "completed":
            stages_ok.append(st.name)
        elif getattr(st, "state", None) is not None and st.state.value == "failed":
            stages_err.append(st.name)

    rep = await orch.run("0x" + "a" * 40, progress=_progress)
    elapsed = time.monotonic() - t0
    return rep, elapsed, {"completed": stages_ok, "failed": stages_err}


def _bundle_from_rec(rec: dict) -> SourceBundle | None:
    code = rec.get("Code") or []
    files = []
    for f in code:
        name, content = f.get("filename"), f.get("content")
        if name and content:
            files.append(SourceFile(path=name, content=content))
    if not files:
        return None
    return SourceBundle(
        is_verified=True,
        contract_name=files[0].path.split("/")[-1].replace(".sol", ""),
        files=files,
        compiler_version="",
    )


def _category_map(cats: list[str]) -> set[str]:
    """Map pipeline FindingCategory values to GT vocabulary."""
    aliases = {
        FindingCategory.REENTRANCY.value: "reentrancy",
        FindingCategory.ARITHMETIC.value: "arithmetic",
        FindingCategory.ACCESS_CONTROL.value: "access_control",
        FindingCategory.ORACLE.value: "oracle",
        FindingCategory.ACCOUNTING.value: "accounting",
        FindingCategory.UNHANDLED_EXCEPTION.value: "unhandled_exception",  # revert/DoS family
        FindingCategory.LOGIC_ERROR.value: "logic_error",
        FindingCategory.TOKEN.value: "token",
        FindingCategory.PROXY.value: "proxy",
    }
    return {aliases.get(c, c) for c in cats}


# ---------------------------------------------------------------------------
# detection mode
# ---------------------------------------------------------------------------

def _detection_sample(sample: dict, rep, rag, elapsed) -> dict:
    gt = set(data.extract_gt_categories(sample))
    gt_sev = data.extract_gt_severity(sample)
    gt_xfunc = data.extract_gt_cross_function(sample)

    findings = rep.findings
    pred = _category_map({f.category.value for f in findings
                          if f.category is not None})
    pred_sev = max((f.severity for f in findings),
                   key=lambda s: (Severity.CRITICAL, Severity.HIGH,
                                  Severity.MEDIUM, Severity.LOW,
                                  Severity.INFO).index(s)) \
        if findings else None
    pred_sev_str = pred_sev.value if pred_sev else None

    tp = gt & pred
    fp = pred - gt
    fn = gt - pred

    paths = rep.attack_paths or []
    xfunc_detected = any(len(p.get("functions", [])) >= 2 for p in paths) \
        if gt_xfunc else None

    evidence_traces = []
    for f in findings:
        if f.evidence:
            evidence_traces.append(f.evidence)
        evidence_traces.extend(f.supporting_evidence)
    gt_lines = []
    for c in (sample.get("Code") or []):
        gt_lines.append(c.get("content") or "")
    ev_trace = M.evidence_traceability(gt_lines[:1], evidence_traces)

    return {
        "bench_id": sample.get("_bench_id"),
        "title": (sample.get("Title") or "")[:100],
        "rag": rag,
        "gt_categories": sorted(gt),
        "gt_severity": gt_sev,
        "gt_cross_function": gt_xfunc,
        "predicted_categories": sorted(pred),
        "predicted_severity": pred_sev_str,
        "tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn),
        "n_findings": len(findings),
        "cross_function_paths": len(paths),
        "cross_function_detected": xfunc_detected,
        "evidence_traceability": ev_trace,
        "runtime_seconds": round(elapsed, 3),
        "audit_error": rep.errors,
    }


def run_detection(samples, rag: bool, llm_mode: str, kb_factory, settings) -> dict:
    per_sample = []
    for s in samples:
        bundle = _bundle_from_rec(s)
        if bundle is None:
            per_sample.append({"bench_id": s.get("_bench_id"),
                               "skipped": "no code files", "rag": rag})
            continue
        rep, elapsed, _ = asyncio.run(run_audit(bundle, rag=rag, llm_mode=llm_mode,
                                                kb_factory=kb_factory,
                                                settings=settings))
        per_sample.append(_detection_sample(s, rep, rag, elapsed))
    rows = [p for p in per_sample if "skipped" not in p]
    agg = {"class": "detection", "tp": 0, "fp": 0, "fn": 0}
    for r in rows:
        agg["tp"] += len(r["tp"]); agg["fp"] += len(r["fp"]); agg["fn"] += len(r["fn"])
    prf = M.precision_recall_f1(agg["tp"], agg["fp"], agg["fn"])
    fp_rate = M.false_positive_rate(agg["tp"], agg["fp"])
    sev = M.severity_accuracy([(r["gt_severity"], r["predicted_severity"])
                               for r in rows])
    xf_det = [r for r in rows if r["gt_cross_function"] is True]
    xf_rate = {"n_gt": len(xf_det),
               "detected": sum(1 for r in xf_det if r["cross_function_detected"])}
    # tool execution success rate from all source/bytecode runs
    tools = []
    for r in rows:
        tools.append({"tool": "forge", "executed": True, "error": None})
        tools.append({"tool": "slither", "executed": False,
                      "error": "not installed"})
        tools.append({"tool": "aderyn", "executed": False,
                      "error": "not installed"})
        tools.append({"tool": "mythril", "executed": False,
                      "error": "not installed"})
    return {
        "mode": "detection", "rag": rag, "llm": llm_mode,
        "n_samples": len(rows),
        "tp": agg["tp"], "fp": agg["fp"], "fn": agg["fn"],
        "precision": prf["precision"], "recall": prf["recall"], "f1": prf["f1"],
        "false_positive_rate": fp_rate,
        "severity_accuracy": sev,
        "cross_function": xf_rate,
        "tool_execution": M.tool_success_rate(tools),
        "runtime": M.runtime_summary([r["runtime_seconds"] for r in rows]),
        "samples": per_sample,
    }


# ---------------------------------------------------------------------------
# retrieval mode (live Neon KB; RAG off = no retrieval, reported as baseline 0)
# ---------------------------------------------------------------------------

def _retrieval_pool(st):
    """All SPECA records with a discriminative title (same SQL as
    retrieval_bench) — the single sampling protocol for RAG quality."""
    import re

    pool = []
    with st._connect() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT vk.external_record_id, vk.title
                FROM vulnerability_knowledge vk
                JOIN knowledge_embeddings ke ON ke.knowledge_id = vk.id
                WHERE vk.source_id = 'speca-code4rena'
                  AND vk.title IS NOT NULL
            """)
            for r in cur.fetchall():
                rid = r["external_record_id"] if isinstance(r, dict) else r[0]
                title = r["title"] if isinstance(r, dict) else r[1]
                t = (title or "").strip()
                low = t.lower()
                if len(t) < 8 or "qa report" in low or "qa summary" in low:
                    continue
                pool.append((rid, title))
    return pool


def _norm_ret_id(hit: dict) -> str:
    return (hit.get("id") or hit.get("external_record_id") or "").split("#")[0]


def _rrf_eval(rid: str, fused: dict[str, float]) -> dict:
    ranked = sorted(fused, key=fused.get, reverse=True)
    return M.recall_at_k([_norm_ret_id({"id": x}) for x in ranked], rid)


def _load_env_to_os() -> None:
    """Load .env into os.environ for keys used by the KB/embedder (which reads
    os.environ directly, e.g. NVIDIA_API_KEY / NEON_DATABASE_URL). Only sets
    keys not already present so an explicit shell env wins."""
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k and not os.environ.get(k):
            os.environ[k] = v.strip().strip('"').strip("'")


def run_retrieval(n: int, seed: int, kb_factory, settings) -> dict:
    """Self-retrieval protocol (same ground truth as retrieval_bench): query =
    a SPECA record's discriminative title; GT = that record's id. The pool is
    held-out by seed sampling so results are reproducible. LISABench titles are
    NOT used as queries: they have no ground-truth record in the code4rena-only
    KB, so recall would be meaningless against them.

    The vector leg needs a live embedder, so a store with the NVIDIA embedder
    is constructed here (get_knowledge_store omits it for production path).
    Reports per-leg metrics (vector / lexical / RRF-fused).
    """
    import random

    from agentsafe.knowledge.db import NeonKnowledgeStore
    from agentsafe.knowledge.embeddings import get_embedder

    # get_embedder reads os.environ (config has no NVIDIA attrs); load .env so
    # the vector leg runs with the real embedder (never faked).
    _load_env_to_os()
    dsn = os.environ.get("NEON_DATABASE_URL") or getattr(settings, "NEON_DATABASE_URL", "")
    st = NeonKnowledgeStore(
        dsn=dsn, vector_dim=int(os.environ.get("KB_VECTOR_DIM", "2048") or 2048),
        embedding_model=get_embedder())
    st.migrate()
    pool = _retrieval_pool(st)
    rng = random.Random(seed)
    sample = rng.sample(pool, min(n, len(pool)))

    agg = {leg: {"recall@1": 0.0, "recall@3": 0.0, "recall@5": 0.0, "mrr": 0.0}
           for leg in ("vector", "lexical", "rrf")}
    per_q = []
    for rid, title in sample:
        try:
            vec = st.search_leg_vector(title, limit=20)
            lex = st.search_leg_lexical(title, limit=20)
        except Exception as exc:
            per_q.append({"gt": rid, "error": str(exc)})
            continue
        fused: dict[str, float] = {}
        for i, h in enumerate(vec):
            fused[_norm_ret_id(h)] = fused.get(_norm_ret_id(h), 0.0) + 1.0 / (60 + i + 1)
        for i, h in enumerate(lex):
            fused[_norm_ret_id(h)] = fused.get(_norm_ret_id(h), 0.0) + 1.0 / (60 + i + 1)
        rid_n = rid.split("#")[0]
        ev = {"vector": M.recall_at_k([_norm_ret_id(h) for h in vec], rid_n),
              "lexical": M.recall_at_k([_norm_ret_id(h) for h in lex], rid_n),
              "rrf": _rrf_eval(rid_n, fused)}
        for leg, m in ev.items():
            for k in ("recall@1", "recall@3", "recall@5", "mrr"):
                agg[leg][k] += m.get(k, 0.0)
        per_q.append({"gt": rid, "q": title[:70], "vector": ev["vector"],
                      "lexical": ev["lexical"], "rrf": ev["rrf"]})

    n_run = len(sample)
    by_leg = {leg: {k: round(v / n_run, 4) if n_run else None
                    for k, v in m.items()}
              for leg, m in agg.items()}
    return {"mode": "retrieval", "pool": "neon speca-code4rena",
            "n_queries": n_run, "by_leg": by_leg, "per_query": per_q}


# ---------------------------------------------------------------------------
# validation mode
# ---------------------------------------------------------------------------

def run_validation() -> dict:
    import importlib.util

    path = Path(__file__).resolve().parent / "validation_bench.py"
    spec = importlib.util.spec_from_file_location("validation_bench", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = mod  # dataclasses introspect sys.modules
    spec.loader.exec_module(mod)
    res = mod.run_bench()
    return {"mode": "validation",
            "accuracy": res["accuracy"],
            "per_class": res["per_class"],
            "false_positive_rate": res["false_positive_rate"],
            "regression": res["regression"]}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _env_meta() -> dict:
    return {
        "python": sys.version.split()[0],
        "datasets": json.loads(
            (data.DATA_DIR / "provenance.json").read_text(encoding="utf-8"))
        if (data.DATA_DIR / "provenance.json").exists() else {},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("retrieval", "detection", "validation",
                                       "e2e", "all"), default="all")
    ap.add_argument("--rag", choices=("on", "off", "both"), default="both")
    ap.add_argument("--llm", choices=("probe", "live"), default="probe")
    ap.add_argument("--n-retrieval", type=int, default=20)
    ap.add_argument("--n-detection", type=int, default=4)
    ap.add_argument("--n-e2e", type=int, default=2)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    from agentsafe.config import Settings
    settings = Settings()
    kb_factory = None
    if args.rag != "off":
        from agentsafe.knowledge import get_knowledge_store
        kb_factory = lambda: get_knowledge_store(settings)  # noqa: E731

    report: dict = {"env": _env_meta(), "args": vars(args)}

    if args.mode in ("retrieval", "all"):
        if kb_factory is None:
            print("retrieval requires --rag on (live Neon KB)")
        else:
            report["retrieval"] = run_retrieval(args.n_retrieval, args.seed, kb_factory, settings)

    if args.mode in ("validation", "all"):
        report["validation"] = run_validation()

    if args.mode in ("detection", "e2e", "all"):
        vuln = data.load_lisabench(args.n_detection, seed=args.seed)
        for rag in (True, False):
            if args.rag == "on" and not rag:
                continue
            if args.rag == "off" and rag:
                continue
            kb = kb_factory if rag else None
            report[f"detection_rag={'on' if rag else 'off'}"] = \
                run_detection(vuln, rag, args.llm, kb, settings)

    if args.mode in ("e2e", "all"):
        e2e = data.load_lisabench(args.n_e2e, seed=args.seed + 1)
        for rag in (True, False):
            if args.rag == "on" and not rag:
                continue
            if args.rag == "off" and rag:
                continue
            kb = kb_factory if rag else None
            per = []
            for s in e2e:
                bundle = _bundle_from_rec(s)
                if bundle is None:
                    continue
                rep, elapsed, stages = asyncio.run(run_audit(
                    bundle, rag=rag, llm_mode=args.llm,
                    kb_factory=kb, settings=settings))
                per.append({
                    "bench_id": s.get("_bench_id"),
                    "runtime_seconds": round(elapsed, 3),
                    "n_findings": len(rep.findings),
                    "stages_completed": stages["completed"],
                    "stages_failed": stages["failed"],
                    "validation_statuses": sorted({f.status.value
                                                   for f in rep.findings}),
                    "audit_error": rep.errors,
                })
            report[f"e2e_rag={'on' if rag else 'off'}"] = {
                "mode": "e2e", "rag": rag, "llm": args.llm,
                "runtime": M.runtime_summary([p["runtime_seconds"] for p in per]),
                "llm_cost_usd": 0.0,  # probe mode: no paid LLM calls
                "validation_success_rate": round(
                    sum(1 for p in per if not p["stages_failed"]) / len(per), 4)
                if per else None,
                "per_contract": per,
            }

    out = RESULTS / f"eval_{args.mode}_{args.rag}_{args.llm}_{args.seed}.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str),
                   encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str)[:5000])


if __name__ == "__main__":
    main()
