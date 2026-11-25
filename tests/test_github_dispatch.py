"""Dispatch robustness (Sections 16 + production fix).

Pins the fix for the production failure where an audit never produced a run:
- the dispatch target (repo default branch + workflow) is resolved with
  read-only calls, so a wrong `GITHUB_REF` cannot cause a silent 404;
- a missing workflow raises a clear error listing what IS available;
- a rejected dispatch surfaces the exact HTTP status + body.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import respx

from agentsafe.github_client import GitHubActionsClient, GitHubClientError

BASE = "https://api.github.com"


async def _ns(_):
    return None


def _client(**kw) -> GitHubActionsClient:
    return GitHubActionsClient(
        token="t", repo="o/r", workflow_file="audit.yml", ref="main",
        sleeper=_ns, resolve_attempts=3, poll_interval_seconds=0.0, **kw,
    )


class TestResolveDispatchTarget:
    @respx.mock
    def test_uses_repo_default_branch(self):
        respx.get(f"{BASE}/repos/o/r").mock(
            return_value=httpx.Response(200, json={"default_branch": "trunk"})
        )
        respx.get(f"{BASE}/repos/o/r/actions/workflows").mock(
            return_value=httpx.Response(200, json={"workflows": [
                {"id": 7, "path": ".github/workflows/audit.yml",
                 "name": "agentSAFE Contract Audit"},
            ]})
        )
        info = asyncio.run(_client().resolve_dispatch_target())
        assert info["ref"] == "trunk"        # not the configured hard-coded "main"
        assert info["workflow"] == "audit.yml"
        assert info["workflow_id"] == 7

    @respx.mock
    def test_missing_workflow_lists_available(self):
        respx.get(f"{BASE}/repos/o/r").mock(
            return_value=httpx.Response(200, json={"default_branch": "main"})
        )
        respx.get(f"{BASE}/repos/o/r/actions/workflows").mock(
            return_value=httpx.Response(200, json={"workflows": [
                {"id": 1, "path": ".github/workflows/other.yml"},
            ]})
        )
        try:
            asyncio.run(_client().resolve_dispatch_target())
            raise AssertionError("expected GitHubClientError")
        except GitHubClientError as exc:
            assert "not dispatchable" in str(exc)
            assert "other.yml" in str(exc)


class TestDispatchSurfacesError:
    @respx.mock
    def test_404_body_is_included(self):
        respx.get(f"{BASE}/repos/o/r").mock(
            return_value=httpx.Response(200, json={"default_branch": "main"})
        )
        respx.get(f"{BASE}/repos/o/r/actions/workflows").mock(
            return_value=httpx.Response(200, json={"workflows": [
                {"id": 7, "path": ".github/workflows/audit.yml"},
            ]})
        )
        respx.post(f"{BASE}/repos/o/r/actions/workflows/audit.yml/dispatches").mock(
            return_value=httpx.Response(404, json={"message": "Not Found"})
        )
        try:
            asyncio.run(_client().trigger_workflow("0x" + "11" * 20, "task1"))
            raise AssertionError("expected GitHubClientError")
        except GitHubClientError as exc:
            assert "404" in str(exc)
            assert "Not Found" in str(exc)

    @respx.mock
    def test_successful_dispatch_uses_default_branch_and_returns_run_id(self):
        respx.get(f"{BASE}/repos/o/r").mock(
            return_value=httpx.Response(200, json={"default_branch": "release"})
        )
        respx.get(f"{BASE}/repos/o/r/actions/workflows").mock(
            return_value=httpx.Response(200, json={"workflows": [
                {"id": 7, "path": ".github/workflows/audit.yml"},
            ]})
        )
        disp = respx.post(
            f"{BASE}/repos/o/r/actions/workflows/audit.yml/dispatches"
        ).mock(return_value=httpx.Response(204))
        respx.get(f"{BASE}/repos/o/r/actions/workflows/audit.yml/runs").mock(
            return_value=httpx.Response(200, json={"workflow_runs": [
                {"id": 123, "created_at": "2999-01-01T00:00:00Z"},
            ]})
        )
        rid = asyncio.run(_client().trigger_workflow("0x" + "11" * 20, "task1"))
        assert rid == 123
        body = json.loads(disp.calls.last.request.content)
        assert body["ref"] == "release"  # resolved default branch, not "main"
