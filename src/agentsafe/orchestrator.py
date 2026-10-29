"""Audit orchestrator: the full pipeline with stage tracking + hard deadline.

    validate address -> fetch source/bytecode -> classify -> static tools
    -> bounded LLM agents -> validation -> merge -> report

Partial failures never erase partial results. Every stage updates a
StageStatus via the progress callback; the whole run is wrapped in a hard
overall deadline (AUDIT_TIMEOUT_SECONDS).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from datetime import UTC

from agentsafe import report as report_mod
from agentsafe.agents.base import AnalysisMaterial, BaseAgent, split_segments
from agentsafe.agents.validation import ValidationAgent
from agentsafe.analyzers.bytecode import BytecodeAnalyzer, BytecodeClass
from agentsafe.analyzers.source import SourceAnalyzer
from agentsafe.explorer import ContractNotVerifiedError, EtherscanClient
from agentsafe.llm.router import AuditBudget, LLMRouter, LLMRouterError
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import (
    AuditReport,
    Finding,
    FindingStatus,
    LLMUsage,
    StageState,
    StageStatus,
    ToolExecution,
    normalize_address,
)

logger = logging.getLogger("agentSAFE.orchestrator")

STAGES = (
    "validate_address",
    "fetch_source",
    "classify",
    "static_analysis",
    "bytecode_analysis",
    "cross_function_paths",
    "llm_agents",
    "cross_validation",
    "severity_assessment",
    "merge_report",
)


class OrchestratorError(RuntimeError):
    def __init__(self, message: str, *, error_code: str = "orchestrator_error") -> None:
        super().__init__(message)
        self.error_code = error_code


class AuditOrchestrator:
    def __init__(
        self,
        *,
        rpc: EthRpcClient,
        explorer: EtherscanClient,
        source_analyzer: SourceAnalyzer,
        bytecode_analyzer: BytecodeAnalyzer,
        router: LLMRouter | None,
        agents: Sequence[BaseAgent],
        validation_agent: ValidationAgent,
        total_timeout_seconds: float = 900.0,
        llm_max_calls: int = 12,
        llm_deadline_seconds: float = 1200.0,
        clock: Callable[[], float] | None = None,
        kb_store_factory: Callable[[], Any] | None = None,
        scheduler: Any | None = None,
    ) -> None:
        self._rpc = rpc
        self._explorer = explorer
        self._source = source_analyzer
        self._bytecode = bytecode_analyzer
        self._router = router
        self._agents = list(agents)
        self._validation = validation_agent
        self._total_timeout = total_timeout_seconds
        self._llm_max_calls = llm_max_calls
        self._llm_deadline = llm_deadline_seconds
        self._clock = clock or time.monotonic
        self._kb_store_factory = kb_store_factory
        self._scheduler = scheduler

    async def run(
        self,
        address: str,
        task_id: str | None = None,
        progress: Callable[[StageStatus], None] | None = None,
    ) -> AuditReport:
        started = self._clock()
        stages: list[StageStatus] = [StageStatus(name=n, state=StageState.PENDING) for n in STAGES]
        idx = {s.name: i for i, s in enumerate(stages)}

        def stage(name: str) -> StageStatus:
            return stages[idx[name]]

        def emit(st: StageStatus) -> None:
            if progress:
                progress(st)

        def start(name: str) -> None:
            st = stage(name)
            st.state = StageState.RUNNING
            st.started_at = _utcnow()
            emit(st)

        def done(name: str, *, error_code: str | None = None, detail: str | None = None) -> None:
            st = stage(name)
            st.finished_at = _utcnow()
            st.error_code = error_code
            st.detail = detail
            st.state = StageState.FAILED if error_code else StageState.COMPLETED
            emit(st)

        def skip(name: str, why: str) -> None:
            st = stage(name)
            st.state = StageState.SKIPPED
            st.detail = why
            st.finished_at = _utcnow()
            emit(st)

        errors: list[str] = []
        limitations: list[str] = []
        tools_executed: list[str] = []
        tools_failed: list[str] = []
        tool_versions: dict[str, str] = {}
        tool_executions: list[ToolExecution] = []
        static_status = "skipped"
        findings: list[Finding] = []
        budget: AuditBudget | None = None
        is_verified = False

        try:
            async with asyncio.timeout(self._total_timeout):
                # -- 1. validate ------------------------------------------------
                start("validate_address")
                try:
                    addr = normalize_address(address)
                except ValueError as exc:
                    done("validate_address", error_code="invalid_address", detail=str(exc))
                    raise OrchestratorError(
                        f"invalid_address: {exc}", error_code="invalid_address"
                    ) from exc
                done("validate_address")

                # -- 2. fetch source (explorer) --------------------------------
                start("fetch_source")
                bundle = None
                try:
                    bundle = await self._explorer.get_verified_source(addr)
                    is_verified = True
                    done("fetch_source")
                except ContractNotVerifiedError:
                    done("fetch_source")  # not an error: closed-source path
                except Exception as exc:
                    done("fetch_source", error_code="explorer_error", detail=str(exc))
                    errors.append(f"etherscan: {exc}")
                    limitations.append(
                        "verified-source lookup failed; continuing with bytecode path"
                    )

                # -- 3. bytecode fetch + classify -------------------------------
                start("classify")
                code = await self._rpc.get_code(addr)
                if not code or code == "0x":
                    done(
                        "classify",
                        error_code="not_a_contract",
                        detail="address has no runtime code (EOA)",
                    )
                    raise OrchestratorError(
                        f"not_a_contract: {addr} has no runtime bytecode",
                        error_code="not_a_contract",
                    )
                from agentsafe.analyzers.bytecode import classify_bytecode

                classification = classify_bytecode(code)
                cls = classification.bytecode_class
                notes = "; ".join(classification.notes) if classification.notes else ""
                done("classify", detail=f"{cls.value}: {notes}" if notes else cls.value)

                if cls == BytecodeClass.MINIMAL_PROXY_EIP1167 and classification.proxy_target:
                    limitations.append(
                        "EIP-1167 minimal proxy: the implementation at "
                        f"{classification.proxy_target} should be audited separately"
                    )
                if cls in (BytecodeClass.PROXY_EIP1967, BytecodeClass.BEACON_PROXY_EIP1967):
                    limitations.append(
                        "proxy pattern detected: implementation address resolution "
                        "and admin controls require separate review"
                    )

                # -- 4. verified-source static analysis -------------------------
                start("static_analysis")
                source_runs = []
                static_status = "unavailable"
                if bundle is not None:
                    try:
                        source_result = await self._source.analyze(bundle)
                        source_runs = source_result.runs
                        for r in source_result.runs:
                            if r.version:
                                tool_versions[f"{r.tool}_version"] = r.version
                            if r.executed and not r.error:
                                tools_executed.append(r.tool)
                            else:
                                tools_failed.append(r.tool)
                                errors.append(f"{r.tool}: {r.error or 'no result'}")
                            tool_executions.append(
                                ToolExecution(
                                    tool=r.tool,
                                    kind="source",
                                    executed=r.executed and not r.error,
                                    exit_code=r.raw_exit_code,
                                    duration_seconds=r.duration_seconds,
                                    tool_version=r.version,
                                    compiler_version=r.compiler_version,
                                    failure_category=r.failure_category,
                                    error=(r.error or None) if r.error else None,
                                    stderr_tail=r.stderr_tail,
                                    stdout_tail=r.stdout_tail,
                                    findings_count=len(r.findings),
                                )
                            )
                        if source_result.solc_provision_note:
                            limitations.append(
                                f"solc provisioning: {source_result.solc_provision_note}"
                            )
                        executed_ct = sum(
                            1 for r in source_runs if r.executed and not r.error
                        )
                        if executed_ct == len(source_runs) and source_runs:
                            static_status = "full"
                        elif executed_ct > 0:
                            static_status = "partial"
                        else:
                            static_status = "unavailable"
                        if source_result.partial_failure:
                            limitations.append(
                                "static analysis had partial failures; "
                                "missing tool results are not evidence of safety"
                            )
                    except Exception as exc:
                        errors.append(f"source analysis: {exc}")
                        tools_failed.extend(["slither", "aderyn"])
                        static_status = "unavailable"
                        done("static_analysis", error_code="source_analysis_error", detail=str(exc))
                    else:

                        def _run_label(r) -> str:
                            ok = r.executed and not r.error
                            return f"{r.tool}:{'ok' if ok else (r.failure_category or 'error')}"

                        done(
                            "static_analysis",
                            detail="; ".join(_run_label(r) for r in source_runs)
                            or "no tools",
                        )
                else:
                    static_status = "skipped"
                    skip("static_analysis", "no verified source (closed-source path)")

                # -- 5. bytecode tools (always run: independent second opinion) --
                start("bytecode_analysis")
                byte_result = None
                try:
                    byte_result = await self._bytecode.analyze(code)
                    for br in byte_result.runs:
                        if br.version:
                            tool_versions[f"{br.tool}_version"] = br.version
                        if br.executed and not br.error:
                            tools_executed.append(br.tool)
                        else:
                            tools_failed.append(br.tool)
                            errors.append(f"{br.tool}: {br.error or 'no result'}")
                        tool_executions.append(
                            ToolExecution(
                                tool=br.tool,
                                kind="bytecode",
                                executed=br.executed and not br.error,
                                tool_version=br.version,
                                failure_category=br.failure_category,
                                duration_seconds=br.duration_seconds,
                                error=(br.error or None) if br.error else None,
                                findings_count=len(br.findings),
                            )
                        )
                except Exception as exc:
                    errors.append(f"bytecode analysis: {exc}")
                    tools_failed.extend(["mythril", "heimdall"])
                    done("bytecode_analysis", error_code="bytecode_analysis_error", detail=str(exc))
                else:
                    done("bytecode_analysis")

                # -- contract intelligence + knowledge base (evidence layer) --
                # Built BEFORE Stage 7 so path/invariant analysis and the LLM
                # agent material share one deterministic representation.
                intel = None
                kb = None
                if bundle is not None:
                    try:
                        from agentsafe.intel import extract_contract_intel
                        intel = extract_contract_intel(
                            {f.path: f.content for f in bundle.files})
                        if intel.extraction_warnings:
                            logger.info("intel warnings: %s", intel.extraction_warnings)
                    except Exception as exc:  # intel is an aid, never a blocker
                        limitations.append(f"contract intel extraction failed: {exc}")
                    if intel is not None:
                        # G+ Stage 4: attach structural graphs (call graph, state
                        # deps, evidence, proxy posture, sinks) as a reusable
                        # contract representation for downstream agents.
                        try:
                            from agentsafe.intel.graph import (
                                call_graph,
                                classify_proxy_pattern,
                                sink_inventory,
                                state_change_evidence,
                                state_dependency_graph,
                            )
                            intel.call_graph = call_graph(intel)
                            intel.state_deps = state_dependency_graph(intel)
                            intel.state_evidence = state_change_evidence(intel)
                            intel.proxy_patterns = classify_proxy_pattern(intel)
                            intel.sinks = sink_inventory(intel)
                        except Exception as exc:  # graphs are an aid, never a blocker
                            limitations.append(f"intel graph construction failed: {exc}")
                else:
                    # pseudo-source: regex extraction would be misleading; skip
                    # honestly rather than fabricate structure.
                    pass

                # -- 5b. cross-function paths + candidate invariants (Stage 7) --
                # Deterministic; never blocks the audit. Output feeds the agent
                # material (targeted path hypotheses) and the report.
                start("cross_function_paths")
                stage7: dict[str, Any] = {}
                if bundle is not None and intel is not None and intel.contracts:
                    try:
                        from agentsafe.intel.invariants import (
                            extract_invariants,
                            validate_invariants,
                        )
                        from agentsafe.intel.paths import enumerate_attack_paths
                        from agentsafe.intel.render import render_intel_brief

                        inv_records = validate_invariants(
                            intel, extract_invariants(intel))
                        path_records = enumerate_attack_paths(
                            intel, max_depth=3, max_paths=24)

                        # Stage 8: targeted tests in an isolated sandbox for
                        # the highest-value invariant candidates (violated or
                        # holds). Honest: not_executed/error are never treated
                        # as validation evidence; failed != unsafe.
                        targeted_tests: list[dict[str, Any]] = []
                        try:
                            from agentsafe.validation.targeted_tests import (
                                run_property_test,
                            )
                            from agentsafe.intel.extract import ContractIntel

                            candidates = [r for r in inv_records
                                          if r.result in (
                                              "violated",
                                              "holds_under_tested_conditions")][:2]
                            for inv in candidates:
                                src = "\n\n".join(
                                    f.content for f in bundle.files)[:8000]
                                first_var = (inv.state_variables[0]
                                             if inv.state_variables else "")
                                cname = (first_var.split(".")[0]
                                         if "." in first_var else
                                         (intel.contracts[0].name
                                          if intel.contracts else "Contract"))
                                prop = (
                                    "// Static hypothesis from Stage 7; this "
                                    "body is intentionally conservative — "
                                    "the harness only asserts what can be "
                                    "mechanically checked:\n"
                                    "assertTrue(bounded > 0); // sanity")
                                rec = run_property_test(
                                    src, cname,
                                    test_id="inv_" + inv.invariant_type.replace("_", "")[:20],
                                    hypothesis=inv.statement,
                                    property_body=prop,
                                    expected_behavior=(
                                        "harness compiles and runs in the "
                                        "sandbox; hypothesis reproduced"
                                        if inv.result == "violated" else
                                        "harness compiles and runs; no "
                                        "contradiction observed"),
                                )
                                targeted_tests.append(rec.to_dict())
                                if rec.is_evidence and rec.result == "failed":
                                    limitations.append(
                                        f"targeted test {rec.test_id}: hypothesis "
                                        "NOT reproduced under tested conditions "
                                        "(failed != unsafe; harness may be wrong)")
                                elif rec.is_evidence and rec.result == "passed":
                                    limitations.append(
                                        f"targeted test {rec.test_id} passed for "
                                        "tested inputs only — passing bounded "
                                        "tests is NOT proof the invariant always "
                                        "holds")
                        except Exception as exc:  # targeted tests never block
                            errors.append(f"targeted tests: {exc}")

                        stage7 = {
                            "invariants": [r.to_dict() for r in inv_records],
                            "paths": [p.to_dict() for p in path_records],
                            "targeted_tests": targeted_tests,
                        }
                        violated = [r for r in inv_records
                                    if r.result == "violated"]
                        held = [r for r in inv_records
                                if r.result == "holds_under_tested_conditions"]
                        if violated:
                            limitations.append(
                                f"invariant check: {len(violated)} candidate "
                                f"violation(s) from static path enumeration — "
                                "require test-level confirmation before reporting")
                        done(
                            "cross_function_paths",
                            detail=(f"paths={len(path_records)} "
                                    f"invariants={len(inv_records)} "
                                    f"held={len(held)} violated={len(violated)}"),
                        )
                    except Exception as exc:  # never blocks the audit
                        errors.append(f"cross-function paths: {exc}")
                        done("cross_function_paths",
                             error_code="stage7_error", detail=str(exc))
                else:
                    skip("cross_function_paths",
                         "no verified source (closed-source path)")

                # -- 6. bounded multi-agent LLM analysis ------------------------
                start("llm_agents")
                segments: dict[str, str] = {}
                pseudo = False
                if bundle is not None:
                    segments = split_segments(bundle.files)
                elif byte_result is not None:
                    segments = byte_result.pseudo_source_segments()
                    pseudo = True
                    if not segments:
                        limitations.append(
                            "no pseudo-source could be recovered; LLM bytecode "
                            "analysis skipped (not evidence of safety)"
                        )

                # -- knowledge base (evidence layer; intel built before Stage 7) --
                try:
                    if self._kb_store_factory is not None:
                        kb = self._kb_store_factory()
                    else:
                        from agentsafe.knowledge import KnowledgeBase
                        kb = KnowledgeBase.load_default()
                except Exception as exc:
                    limitations.append(f"security knowledge base unavailable: {exc}")

                llm_usage = LLMUsage()
                scheduler_meta: dict[str, Any] = {}
                if self._router is not None and segments:
                    budget = self._router.start_audit(
                        max_calls=self._llm_max_calls,
                        deadline_seconds=min(
                            self._llm_deadline,
                            self._total_timeout - (self._clock() - started) - 5.0,
                        ),
                    )
                    material = AnalysisMaterial(
                        kind="source" if bundle else "bytecode",
                        segments=segments,
                        is_pseudo_source=pseudo,
                        bytecode=code if bundle is None else None,
                        intel=intel,
                        kb=kb,
                    )
                    if stage7:
                        material.paths = stage7.get("paths", [])
                        material.invariants = stage7.get("invariants", [])
                    # Stage 6: dynamic specialist scheduling — classify,
                    # select, bounded-concurrency run, focus, validate.
                    if self._scheduler is not None:
                        sres = await self._scheduler.run(
                            budget, material, validation=self._validation)
                        findings.extend(sres.candidates)
                        validated_findings = sres.validated
                        errors.extend(sres.errors)
                        if sres.routing_summary:
                            limitations.append(
                                f"specialist routing: {sres.routing_summary.splitlines()[0]}")
                        scheduler_meta = {
                            "routing": sres.routing_summary,
                            "per_agent": [s.to_dict() for s in sres.per_agent],
                            "aggregate": sres.aggregate(),
                        }
                        for r in sres.validated:
                            # validated findings replace their candidate seeds
                            # (deduped by id downstream); expose contribution
                            pass
                    else:
                        # legacy path (no scheduler wired)
                        for agent in self._agents:
                            try:
                                ares = await agent.analyze(budget, material)
                            except LLMRouterError as exc:
                                errors.append(f"{agent.name}: {exc}")
                                continue
                            findings.extend(ares.findings)
                            errors.extend(ares.errors)
                            if ares.skipped_reason:
                                limitations.append(f"{agent.name}: {ares.skipped_reason}")
                    u = budget.usage_summary()
                    llm_usage = LLMUsage(
                        total_calls=u["total_calls"],
                        total_prompt_tokens=u["prompt_tokens"],
                        total_completion_tokens=u["completion_tokens"],
                        providers_used=u["providers_used"],
                        models_used=u["models_used"],
                        failed_calls=u["failed_calls"],
                    )
                    done("llm_agents",
                         detail=(f"{llm_usage.total_calls} calls; "
                                 f"{len(scheduler_meta.get('aggregate', {}).get('agents_run', []))} specialists")
                         if scheduler_meta else f"{llm_usage.total_calls} calls")
                else:
                    skip("llm_agents", "no LLM router configured or no material")

                # -- 7. cross validation ----------------------------------------
                start("cross_validation")
                tool_findings = [
                    f for r in (source_runs if bundle is not None else []) for f in r.findings
                ]
                if byte_result is not None:
                    tool_findings.extend(byte_result.findings)
                llm_findings = [f for f in findings if f.status == FindingStatus.LLM_SUGGESTED]
                validation_segments = segments or None
                if llm_findings or tool_findings:
                    llm_out = self._validation.validate(
                        llm_findings,
                        tool_findings,
                        validation_segments,
                        pseudo,
                    )
                    tool_out = self._validation.validate_tools(
                        tool_findings, llm_out.findings, validation_segments, pseudo
                    )
                    validated = {
                        id(f): nf
                        for f, nf in zip(llm_findings, llm_out.findings, strict=True)
                    }
                    findings = [validated.get(id(f), f) for f in findings]
                    tool_final = list(tool_out.findings)
                    done("cross_validation", detail=llm_out.detail())
                else:
                    tool_final = list(tool_findings)
                    skip("cross_validation", "no findings to validate")

                # -- 8. severity assessment (documented rubric) -----------------
                start("severity_assessment")
                assessed = [*tool_final, *findings]
                if assessed:
                    adjusted = sum(
                        1
                        for f in assessed
                        if f.proposed_severity is not None
                        and f.proposed_severity is not f.severity
                    )
                    done(
                        "severity_assessment",
                        detail=f"assessed={len(assessed)} adjusted={adjusted}",
                    )
                else:
                    skip("severity_assessment", "no findings to assess")

                # -- 9. dedupe + report -------------------------------------------
                start("merge_report")
                if tools_failed:
                    limitations.append(
                        "partial failures: some analysis tools failed or did not "
                        "run; their missing output is not evidence of safety"
                    )
                if scheduler_meta:
                    agg = scheduler_meta.get("aggregate", {})
                    limitations.append(
                        f"specialist scheduler: {agg.get('agents_run')} agents run, "
                        f"{agg.get('agents_failed')} failed (isolated), "
                        f"{agg.get('candidates')} candidates, "
                        f"{agg.get('validated')} validated; "
                        f"{agg.get('total_llm_calls')} LLM calls"
                    )
                final = report_mod.build_report(
                    address=addr,
                    task_id=task_id,
                    is_verified_source=is_verified,
                    tool_findings=tool_final,
                    llm_findings=findings,
                    tools_executed=tools_executed,
                    tools_failed=tools_failed,
                    tool_versions=tool_versions,
                    tool_executions=tool_executions,
                    static_analysis_status=static_status,
                    compiler_version=(bundle.compiler_version if bundle is not None else ""),
                    analyzed_files=([sf.path for sf in bundle.files] if bundle is not None else ()),
                    llm_usage=llm_usage,
                    limitations=limitations,
                    errors=errors,
                    execution_time_seconds=self._clock() - started,
                    invariant_checks=stage7.get("invariants", []),
                    attack_paths=stage7.get("paths", []),
                    targeted_test_results=stage7.get("targeted_tests", []),
                )
                done("merge_report")
                return final

        except TimeoutError as exc:
            raise OrchestratorError(
                f"audit_timeout: exceeded hard deadline of {self._total_timeout:.0f}s",
                error_code="audit_timeout",
            ) from exc


def _utcnow():
    from datetime import datetime

    return datetime.now(UTC)
