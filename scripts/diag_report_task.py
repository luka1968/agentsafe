"""Diagnose why report retrieval returns HTTP 500 for a task.

Reproduces the server's _serve_rendered_report fetch/validate/render chain
locally with the SAME code, token, and GitHub client the deployment uses, so a
bare "Internal Server Error" in production can be root-caused here.

Usage:
    .venv\\Scripts\\python.exe scripts\\diag_report_task.py --task tf8Gq6xWi2z8sEp3AyMGyvMM

Prints only run/artifact ids and error classes/messages - never tokens.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from agentsafe.config import Settings
from agentsafe.github_client import GitHubActionsClient, GitHubClientError
from agentsafe.schemas import AuditReport
from agentsafe.report_render import render_html, render_markdown


async def _find_run_for_task(gh: GitHubActionsClient, task_id: str) -> int | None:
    """Find the workflow run whose artifact name matches this task."""
    artifact_name = f"docker-audit-report-{task_id}"
    per_page = 100
    page = 1
    while page <= 5:
        resp = await gh._request(
            "GET",
            f"/repos/{gh._repo}/actions/artifacts",
            params={"per_page": str(per_page), "page": str(page)},
        )
        artifacts = (resp.json() or {}).get("artifacts") or []
        for a in artifacts:
            name = a.get("name") or ""
            if name == artifact_name:
                run_id = a.get("workflow_run", {}).get("id") or a.get("run_id")
                return run_id
        if len(artifacts) < per_page:
            break
        page += 1
    return None


async def main(task_id: str) -> int:
    s = Settings()
    gh = GitHubActionsClient(
        token=s.GITHUB_TOKEN,
        repo=s.GITHUB_REPO,
        workflow_file=s.GITHUB_WORKFLOW_FILE,
        ref=s.GITHUB_REF,
        timeout_seconds=s.GITHUB_API_TIMEOUT_SECONDS,
        poll_interval_seconds=s.GITHUB_POLL_INTERVAL_SECONDS,
        resolve_attempts=s.GITHUB_RUN_RESOLVE_ATTEMPTS,
        strict=True,
    )
    try:
        run_id = await _find_run_for_task(gh, task_id)
        print(f"task={task_id} run_id={run_id}")
        if not run_id:
            print("RESULT: NO run found with artifact docker-audit-report-<task>")
            return 3
        print("fetching run...")
        run = await gh.get_run(run_id)
        print(f"run.status={run.get('status')} run.conclusion={run.get('conclusion')}")
        print("fetching + parsing report.json...")
        report = await gh.fetch_report(run_id, task_id)
        print(f"report.json parsed, top-level keys={len(report)}")
        print("validating AuditReport...")
        validated = AuditReport.model_validate(report)
        print(f"validate OK: {len(validated.findings)} findings, "
              f"summary.tools_executed={validated.summary.tools_executed}")
        for name, fn in (("html", render_html), ("markdown", render_markdown)):
            try:
                out = fn(validated)
                print(f"render {name}: OK ({len(out)} bytes)")
            except Exception as exc:  # noqa: BLE001
                print(f"render {name}: FAILED -> {type(exc).__name__}: {exc}")
        print("RESULT: ALL_OK")
        return 0
    except GitHubClientError as exc:
        print(f"RESULT: GitHubClientError: {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"RESULT: UNEXPECTED {type(exc).__name__}: {exc}")
        return 1
    finally:
        await gh.aclose()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--task", required=True)
    args = p.parse_args()
    sys.exit(asyncio.run(main(args.task)))