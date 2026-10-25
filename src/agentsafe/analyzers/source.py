"""Verified-source static analysis: Slither + Aderyn.

CLI contract note (aderyn invocation verified against the pinned release
aderyn-v0.6.8 `aderyn/src/main.rs`; slither flag verified against slither
0.10.x docs; the CI smoke test must re-confirm both on the pinned versions):

  slither <dir> --json -            -> JSON on stdout
  aderyn <dir> --output report.json -> JSON written to <dir>/report.json
                                        (format selected by file extension;
                                        there is NO --json flag in 0.6.x)

Slither JSON shape:
  {"success": bool, "error": null, "results": {"detectors": [
     {"check": str, "impact": High|Medium|Low|Informational|Optimization,
      "confidence": str, "description": str,
      "elements": [{"type": str, "name": str,
        "source_mapping": {"lines": [int...],
                           "filename": {"short": str}}}]}]}}

Aderyn JSON shape:
  {"files": [str], "issues": {"high": [{"title": str,
      "instances": [{"contract": str, "line": int}]}], "low": [...]},
   "summary": {...}}

If real output does not match, the parser records a tool error and fabricates
NOTHING. A tool that fails must never be reported as "no issues found".
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsafe.schemas import Finding, FindingStatus, Severity

from .proc import (
    AnalyzerError,
    DefaultSubprocessRunner,
    ProcResult,
    ProcSpec,
    SubprocessRunner,
    TempWorkspace,
)

logger = logging.getLogger("agentSAFE.source")

MAX_SOURCE_TOTAL_BYTES = 5_000_000

# Documented failure taxonomy (mirrored in schemas.ToolExecution docs).
CAT_NOT_INSTALLED = "not_installed"
CAT_TIMEOUT = "timeout"
CAT_SPAWN_ERROR = "spawn_error"
CAT_NO_OUTPUT = "no_output"
CAT_COMPILE_ERROR = "compile_error"
CAT_PARSE_ERROR = "parse_error"
CAT_TOOL_ERROR = "tool_error"
CAT_NONZERO_NO_FINDINGS = "nonzero_exit_no_findings"
CAT_SIZE_POLICY = "size_policy"

# Markers observed in slither/crytic-compile stderr when the solc invocation
# itself failed (as opposed to the tool crashing or emitting nothing).
_COMPILE_ERROR_MARKERS = (
    "error compiling",
    "compilation error",
    "compilation failed",
    "unable to compile",
    "syntaxerror",
    "parsererror",
    "declarationerror",
    "typeerror",
    "unimplemented feature",
    "source file requires different compiler version",
)

_SOLC_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")

_SLITHER_IMPACT = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "optimization": Severity.INFO,
}


@dataclass
class ToolRun:
    """Result of one tool run. executed=False means "we know nothing".

    Diagnostics (exit code, duration, versions, failure category, output
    tails) are captured for EVERY attempt so reports can explain partial
    analysis instead of silently omitting tools.
    """

    tool: str
    executed: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    version: str | None = None
    raw_exit_code: int | None = None
    duration_seconds: float | None = None
    compiler_version: str | None = None
    failure_category: str | None = None
    stderr_tail: str | None = None
    stdout_tail: str | None = None


@dataclass
class SourceAnalysis:
    runs: list[ToolRun]
    partial_failure: bool
    solc_selected: str | None = None
    solc_provision_note: str | None = None

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.runs:
            out.extend(r.findings)
        return out


class SourceAnalyzer:
    """Runs Slither and Aderyn over a preserved multi-file source project."""

    def __init__(
        self,
        *,
        slither_bin: str = "slither",
        aderyn_bin: str = "aderyn",
        runner: SubprocessRunner | None = None,
        tool_timeout_seconds: float = 300.0,
        max_output_bytes: int = 2_000_000,
        total_source_cap_bytes: int = MAX_SOURCE_TOTAL_BYTES,
    ) -> None:
        self._slither = slither_bin
        self._aderyn = aderyn_bin
        self._runner: SubprocessRunner = runner or DefaultSubprocessRunner()
        self._timeout = tool_timeout_seconds
        self._max_output = max_output_bytes
        self._source_cap = total_source_cap_bytes

    async def _version(self, executable: str) -> str | None:
        """Best-effort version probe; failure is non-fatal."""
        res = await self._runner.run(
            ProcSpec(
                executable=executable,
                args=["--version"],
                cwd=Path("."),
                timeout_seconds=30.0,
                max_output_bytes=4096,
            )
        )
        if res.missing or res.timed_out or res.error:
            return None
        text = (res.stdout or b"").decode("utf-8", "replace").strip()
        if not text:
            text = (res.stderr or b"").decode("utf-8", "replace").strip()
        m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
        return m.group(1) if m else (text[:40] or None)

    async def analyze(self, bundle) -> SourceAnalysis:
        """Materialize the source project into a temp workspace and run tools.

        The workspace is always removed in finally. Tool failures are isolated:
        one tool failing never suppresses the other's results.
        """
        if not bundle or not getattr(bundle, "files", None):
            raise AnalyzerError("no source files to analyze")

        # Root cause of the first WETH audit failing Slither with an opaque
        # "no JSON output" error (verified in a container repro): crytic-compile
        # compiles with solc-select's GLOBAL version and does NOT pick a
        # pragma-compatible one, and slither exits 1 silently when the global
        # solc cannot compile the source. Provision the Etherscan-recorded
        # compiler version and pin it per-process via SOLC_VERSION.
        solc_version, solc_note = await self._ensure_solc(
            getattr(bundle, "compiler_version", "")
        )

        runs: list[ToolRun] = []
        workspace = TempWorkspace.create()
        try:
            self._materialize(bundle, workspace)
            root = workspace.root
            runs.append(await self._run_slither(root, solc_version))
            runs.append(await self._run_aderyn(root))
        finally:
            workspace.cleanup()

        partial = any((not r.executed) or (r.error is not None) for r in runs)
        return SourceAnalysis(
            runs=runs,
            partial_failure=partial,
            solc_selected=solc_version,
            solc_provision_note=solc_note,
        )

    async def _ensure_solc(self, compiler_version: str) -> tuple[str | None, str | None]:
        """Ensure the Etherscan-recorded solc version is installed.

        Returns (version_to_pin, provision_note). The note is None on success
        or when no version was requested; it records WHY pinning was skipped
        so reports can surface the root cause instead of an opaque failure.
        ``solc-select install`` is idempotent: an already-installed version is
        a fast no-op.
        """
        m = _SOLC_VERSION_RE.search(compiler_version or "")
        if not m:
            return None, None
        version = m.group(1)
        res = await self._runner.run(
            ProcSpec(
                executable="solc-select",
                args=["install", version],
                cwd=Path("."),
                timeout_seconds=120.0,
                max_output_bytes=4096,
            )
        )
        if res.missing:
            # solc-select absent (e.g. dev machine): assume the environment
            # already provides a usable solc and do not pin.
            note = f"solc-select not installed; solc {version} not pinned"
            logger.warning("solc-select unavailable; not pinning solc %s", version)
            return None, note
        if res.exit_code not in (0, None):
            note = (
                f"solc-select install {version} failed (exit {res.exit_code}); "
                "slither will use the global solc and may fail to compile"
            )
            logger.warning("solc-select install %s failed; slither may fail to compile", version)
            return None, note
        return version, None

    def _materialize(self, bundle, workspace: TempWorkspace) -> None:
        """Write files preserving paths/settings. No concatenation, no truncation."""
        total = 0
        for sf in bundle.files:
            total += len(sf.content.encode("utf-8", "replace"))
            if total > self._source_cap:
                raise AnalyzerError(
                    f"source exceeds {self._source_cap} bytes; refusing to analyze "
                    "a possibly truncated/corrupted copy"
                )
            target = workspace.safe_relpath(sf.path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(sf.content, encoding="utf-8")

        # Preserve compiler settings as a Standard JSON input alongside the files,
        # so Slither's standard-json mode can pick optimizer/EVM settings up.
        if bundle.settings is not None:
            std = {
                "language": bundle.language or "Solidity",
                "sources": {sf.path: {"content": sf.content} for sf in bundle.files},
                "settings": bundle.settings,
            }
            (workspace.root / "standard_input.json").write_text(json.dumps(std), encoding="utf-8")

    async def _run_slither(self, root: Path, solc_version: str | None = None) -> ToolRun:
        run = ToolRun(tool="slither", executed=False, compiler_version=solc_version)
        run.version = await self._version(self._slither)
        started = time.monotonic()
        res = await self._runner.run(
            ProcSpec(
                executable=self._slither,
                args=[str(root), "--json", "-"],
                cwd=root,
                timeout_seconds=self._timeout,
                max_output_bytes=self._max_output,
                # Pin the contract's real compiler for THIS process only;
                # the solc-select shim checks SOLC_VERSION before global.
                extra_env={"SOLC_VERSION": solc_version} if solc_version else None,
            )
        )
        run.duration_seconds = round(time.monotonic() - started, 3)
        run.raw_exit_code = res.exit_code
        run.stderr_tail = _stderr_tail(res.stderr)
        if res.missing:
            run.failure_category = CAT_NOT_INSTALLED
            run.error = f"slither not installed: {res.error}"
            return run
        if res.timed_out:
            run.failure_category = CAT_TIMEOUT
            run.error = f"slither timed out after {self._timeout:.0f}s"
            return run
        if res.error:
            run.failure_category = CAT_SPAWN_ERROR
            run.error = f"slither spawn error: {res.error}"
            return run
        if not (res.stdout or b"").strip():
            # No stdout at all. Exit-code semantics (slither docs): 0 = clean
            # run (findings may exist and appear in JSON); nonzero almost
            # always means compilation/tooling failure. Classify via stderr
            # markers so reports can distinguish compile errors from silence.
            run.failure_category = (
                CAT_COMPILE_ERROR
                if _looks_like_compile_error(run.stderr_tail)
                else CAT_NO_OUTPUT
            )
            run.error = (
                f"slither exited with {res.exit_code} and produced no JSON output "
                f"(category: {run.failure_category})"
            )
            if run.stderr_tail:
                run.error += f"; stderr: {run.stderr_tail}"
            return run
        # stdout exists; keep only a bounded tail for diagnostics (the full
        # body is the JSON payload, parsed below - never stored raw).
        run.stdout_tail = _stdout_tail(res.stdout)

        try:
            findings, tool_err = _parse_slither(res)
        except Exception as exc:  # parser bug guard: record, never fabricate
            run.failure_category = CAT_PARSE_ERROR
            run.error = f"slither output could not be parsed: {exc}"
            return run
        run.findings = findings
        run.executed = True
        if tool_err:
            run.failure_category = CAT_TOOL_ERROR
            run.error = tool_err  # parsed but tool reported its own error
        if res.exit_code not in (0, None) and not findings and not tool_err:
            # Slither's documented behavior: a nonzero exit WITHOUT its JSON
            # results is a tooling failure, not an empty analysis. WETH9
            # regression: exactly this shape (exit 1, silent) = wrong global
            # solc. Kept "executed=False" so "no findings" is never claimed.
            run.failure_category = CAT_NONZERO_NO_FINDINGS
            run.error = f"slither exited with {res.exit_code} and produced no JSON"
            run.executed = False
        return run

    async def _run_aderyn(self, root: Path) -> ToolRun:
        run = ToolRun(tool="aderyn", executed=False)
        run.version = await self._version(self._aderyn)
        # aderyn v0.6.x has no --json flag; the report format is selected by
        # the --output file extension. Relative path + cwd keeps it inside the
        # (already path-guarded) temp workspace.
        report_path = root / "report.json"
        started = time.monotonic()
        res = await self._runner.run(
            ProcSpec(
                executable=self._aderyn,
                args=[str(root), "--output", "report.json"],
                cwd=root,
                timeout_seconds=self._timeout,
                max_output_bytes=self._max_output,
            )
        )
        run.duration_seconds = round(time.monotonic() - started, 3)
        run.raw_exit_code = res.exit_code
        run.stderr_tail = _stderr_tail(res.stderr)
        if res.missing:
            run.failure_category = CAT_NOT_INSTALLED
            run.error = f"aderyn not installed: {res.error}"
            return run
        if res.timed_out:
            run.failure_category = CAT_TIMEOUT
            run.error = f"aderyn timed out after {self._timeout:.0f}s"
            return run
        if res.error:
            run.failure_category = CAT_SPAWN_ERROR
            run.error = f"aderyn spawn error: {res.error}"
            return run
        try:
            data = report_path.read_bytes()
        except OSError:
            data = b""
        if not data.strip():
            run.failure_category = (
                CAT_COMPILE_ERROR
                if _looks_like_compile_error(run.stderr_tail)
                else CAT_NO_OUTPUT
            )
            run.error = (
                f"aderyn exited with {res.exit_code} and wrote no report.json "
                f"(category: {run.failure_category})"
            )
            if run.stderr_tail:
                run.error += f"; stderr: {run.stderr_tail}"
            return run

        try:
            findings, tool_err = _parse_aderyn(data)
        except Exception as exc:
            run.failure_category = CAT_PARSE_ERROR
            run.error = f"aderyn output could not be parsed: {exc}"
            return run
        run.findings = findings
        run.executed = True
        if tool_err:
            run.failure_category = CAT_TOOL_ERROR
            run.error = tool_err
        if res.exit_code not in (0, None) and not findings and not tool_err:
            run.failure_category = CAT_NONZERO_NO_FINDINGS
            run.error = f"aderyn exited with {res.exit_code} and wrote no usable JSON"
            run.executed = False
        return run


# --------------------------------------------------------------------------
# Output parsers (module-level pure functions => directly unit-testable)
# --------------------------------------------------------------------------


def _stderr_tail(stderr: bytes, limit: int = 300) -> str:
    """Last `limit` chars of a tool's stderr, for diagnosable error records."""
    return (stderr or b"").decode("utf-8", "replace").strip()[-limit:]


def _stdout_tail(stdout: bytes, limit: int = 300) -> str:
    """Last `limit` chars of stdout, for diagnostics when output existed but
    was not usable. Only stored when the JSON payload itself is absent."""
    return (stdout or b"").decode("utf-8", "replace").strip()[-limit:]


def _looks_like_compile_error(stderr_tail: str | None) -> bool:
    """Classify stderr as a Solidity-compile failure vs generic silence."""
    if not stderr_tail:
        return False
    low = stderr_tail.lower()
    return any(marker in low for marker in _COMPILE_ERROR_MARKERS)


def _parse_slither(res: ProcResult) -> tuple[list[Finding], str | None]:
    data = json.loads((res.stdout or b"").decode("utf-8", "replace"))
    if not isinstance(data, dict):
        raise ValueError("slither JSON root is not an object")
    tool_err: str | None = None
    if data.get("error"):
        tool_err = str(data["error"])[:500]
    results = data.get("results") or {}
    detectors = results.get("detectors") or []
    findings: list[Finding] = []
    for det in detectors:
        if not isinstance(det, dict):
            continue
        check = str(det.get("check") or "unknown-check")
        impact = str(det.get("impact") or "Informational").lower()
        severity = _SLITHER_IMPACT.get(impact, Severity.INFO)
        description = str(det.get("description") or check)
        file_path, line_start, line_end = _first_source_mapping(det)
        findings.append(
            Finding(
                title=f"[slither] {check}",
                severity=severity,
                status=FindingStatus.TOOL_DETECTED,
                source=["slither"],
                detector_id=check,
                description=description,
                evidence=description,  # slither embeds the code snippet here
                recommendation=_slither_recommendation(check),
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                metadata={
                    "tool_impact": impact,
                    "tool_confidence": str(det.get("confidence") or ""),
                    "slither_version_marker": True,
                },
            )
        )
    return findings, tool_err


def _first_source_mapping(det: dict[str, Any]) -> tuple[str | None, int | None, int | None]:
    for el in det.get("elements") or []:
        if not isinstance(el, dict):
            continue
        sm = el.get("source_mapping") or {}
        lines = sm.get("lines") or []
        fname = None
        if isinstance(sm.get("filename"), dict):
            fname = (sm.get("filename") or {}).get("short")
        if lines:
            nums = [int(x) for x in lines if isinstance(x, int)]
            return fname, (min(nums) if nums else None), (max(nums) if nums else None)
        if fname:
            return fname, None, None
    return None, None, None


def _slither_recommendation(check: str) -> str:
    """Honest default: point at the official detector docs, don't invent fixes."""
    return (
        f"Review Slither documentation for detector '{check}' "
        "(https://github.com/crytic/slither/wiki/Detector-Documentation) and fix "
        "the flagged pattern; verify impact before deployment."
    )


_ADERYN_SEVERITY = {"high": Severity.HIGH, "low": Severity.LOW}


def _parse_aderyn(data: bytes) -> tuple[list[Finding], str | None]:
    data_json = json.loads(data.decode("utf-8", "replace"))
    if not isinstance(data_json, dict):
        raise ValueError("aderyn JSON root is not an object")
    issues = data_json.get("issues") or {}
    findings: list[Finding] = []
    for level, entries in issues.items():
        sev = _ADERYN_SEVERITY.get(str(level).lower(), Severity.LOW)
        for issue in entries or []:
            if not isinstance(issue, dict):
                continue
            title = str(issue.get("title") or "unknown-issue")
            detector_id = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
            instances = issue.get("instances") or []
            if not instances:
                findings.append(_aderyn_finding(title, detector_id, sev, None, None, None))
            for inst in instances:
                if not isinstance(inst, dict):
                    continue
                findings.append(
                    _aderyn_finding(
                        title,
                        detector_id,
                        sev,
                        str(inst.get("contract") or "") or None,
                        inst.get("line"),
                        str(inst.get("function") or "") or None,
                    )
                )
    return findings, None


def _aderyn_finding(
    title: str,
    detector_id: str,
    sev: Severity,
    contract: str | None,
    line: int | None,
    function: str | None,
) -> Finding:
    desc = f"Aderyn flagged '{title}'"
    if contract:
        desc += f" in contract {contract}"
    if function:
        desc += f" (function {function})"
    if isinstance(line, int):
        desc += f" at line {line}"
    return Finding(
        title=f"[aderyn] {title}",
        severity=sev,
        status=FindingStatus.TOOL_DETECTED,
        source=["aderyn"],
        detector_id=f"aderyn-{detector_id}",
        description=desc,
        evidence=desc,
        recommendation=(
            f"Review Aderyn documentation for '{title}' "
            "(https://github.com/Cyfrin/aderyn) and remediate the flagged pattern."
        ),
        file_path=None,  # aderyn reports contract/line; path added when available
        line_start=int(line) if isinstance(line, int) and line > 0 else None,
        metadata={"contract": contract, "function": function},
    )
