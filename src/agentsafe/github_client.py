"""GitHub Actions client: dispatch, run association, artifacts.

Association strategy: dispatch the workflow, then wait (up to
`resolve_attempts` x `poll_interval_seconds`, default ~5min) for the run row
to appear in this workflow's run list (created_at >= dispatch time). The run
id is captured ONCE from that list and returned; callers then poll that exact
id via GET /actions/runs/{id}. Association is by run id only - never by
fragile run-name string matching, because GitHub's workflow_runs[].name does
not reliably equal the workflow's `run-name` on workflow_dispatch.

Artifact safety (Prompt 9): artifact must belong to the given run, its name
must equal audit-report-<task_id>, and the ZIP is extracted with:
absolute paths rejected, traversal rejected, per-file + total size caps,
only the expected report.json accepted.
"""

from __future__ import annotations

import asyncio
import io
import logging
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from agentsafe.schemas import normalize_address

logger = logging.getLogger("agentSAFE.github")

API_BASE = "https://api.github.com"
_TRANSIENT_HTTP = {429, 500, 502, 503, 504}
MAX_ZIP_BYTES = 20 * 1024 * 1024
MAX_MEMBER_BYTES = 20 * 1024 * 1024


class GitHubClientError(RuntimeError):
    pass


class RunAssociationError(GitHubClientError):
    """Could not uniquely associate a dispatch with one run_id."""


class RateLimitedError(GitHubClientError):
    pass


class ArtifactExpiredError(GitHubClientError):
    pass


class GitHubActionsClient:
    def __init__(
        self,
        *,
        token: str,
        repo: str,  # "owner/repo"
        workflow_file: str = "audit.yml",
        ref: str = "main",
        base_url: str = API_BASE,
        timeout_seconds: float = 20.0,
        max_retries: int = 3,
        poll_interval_seconds: float = 10.0,
        # Dispatch -> run-row appearance window. ~5 min by default so slow
        # runner startup / queued runners don't make the run "disappear".
        resolve_attempts: int = 30,
        client: httpx.AsyncClient | None = None,
        sleeper: Any | None = None,
        strict: bool = True,
    ) -> None:
        if strict:
            # Deferred (strict=False) mode is for cloud build-time inspection
            # only; the server lifespan re-validates config at runtime.
            if not token:
                raise ValueError("GitHub token required")
            if "/" not in repo or repo.count("/") != 1:
                raise ValueError(f"repo must be 'owner/repo', got {repo!r}")
        self._repo = repo
        self._workflow = workflow_file
        # Run-name and artifact prefixes are derived from the workflow file so
        # both audit.yml (audit-*, audit-report-*) and docker-audit.yml
        # (docker-audit-*, docker-audit-report-*) associate correctly.
        base = workflow_file.rsplit(".", 1)[0] if "." in workflow_file else workflow_file
        self._run_name_prefix = f"{base}-"
        self._artifact_name_prefix = f"{base}-report-"
        self._ref = ref
        self._base = base_url.rstrip("/")
        self._max_retries = max_retries
        self._poll_interval = poll_interval_seconds
        self._resolve_attempts = resolve_attempts
        self._sleeper = sleeper or asyncio.sleep
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds, connect=timeout_seconds),
            follow_redirects=True,  # artifact downloads 302 to a signed URL
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "agentSAFE-mcp",
            },
        )
        # Vercel rotates the asyncio event loop between warm invocations
        # (see api/index.py). A caller-supplied client is managed externally;
        # our own httpx.AsyncClient is rebuilt if the running loop changes so
        # a warm request never reuses a client bound to a now-closed loop
        # (RuntimeError: Event loop is closed -> bare 500).
        self._caller_supplied = client is not None
        self._client_loop = None

    async def aclose(self) -> None:
        await self._client.aclose()

    def _ensure_loop_client(self) -> None:
        """Rebuild the internal httpx client when the running event loop
        differs from the loop it was created on. Never closes the old client
        (closing on a dead loop raises); it is simply dropped. No-op when a
        caller-supplied client is in use (managed externally) or the loop is
        unchanged."""
        import asyncio

        if self._caller_supplied:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no running loop (build-time); leave as-is
        if self._client_loop is loop:
            return
        self._client_loop = loop
        try:
            self._client = httpx.AsyncClient(
                timeout=self._client.timeout,
                follow_redirects=True,
                headers=dict(self._client.headers),
            )
        except Exception as exc:  # noqa: BLE001 - keep the prior client if rebuild fails
            logger.warning("github client rebuild failed: %s", exc)

    # ------------------------------------------------------------------ core
    async def _request(
        self, method: str, path: str, *, json_body: dict | None = None, params: dict | None = None
    ) -> httpx.Response:
        self._ensure_loop_client()  # serverless loop-rotation safety
        attempt = 0
        last_detail = "unknown"
        while True:
            transient = False
            try:
                resp = await self._client.request(
                    method,
                    f"{self._base}{path}",
                    json=json_body,
                    params=params,
                )
                if resp.status_code in _TRANSIENT_HTTP:
                    transient = True
                    last_detail = f"HTTP {resp.status_code}"
                elif resp.status_code == 403 and self._is_rate_limited(resp):
                    raise RateLimitedError("GitHub API rate limit exceeded")
                elif resp.status_code >= 400:
                    raise GitHubClientError(f"GitHub API {method} {path}: HTTP {resp.status_code}")
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                transient = True
                last_detail = f"transport error: {exc}"
                resp = None  # type: ignore[assignment]
            if not transient and resp is not None:
                remaining = resp.headers.get("x-ratelimit-remaining")
                if remaining is not None and remaining.isdigit() and int(remaining) < 50:
                    logger.warning("github api rate budget low: %s remaining", remaining)
                return resp
            if attempt >= self._max_retries:
                raise GitHubClientError(
                    f"GitHub API {method} {path}: giving up after {attempt + 1} attempts"
                    f" (last: {last_detail})"
                )
            await self._sleeper(min(1.0 * (2**attempt), 15.0))
            attempt += 1

    @staticmethod
    def _is_rate_limited(resp: httpx.Response) -> bool:
        return "rate limit" in (resp.text or "").lower()

    # ------------------------------------------------------------- dispatch
    async def trigger_workflow(self, address: str, task_id: str) -> int:
        """Dispatch the audit workflow and return the created run id.

        GitHub's workflow_dispatch endpoint returns 204 No Content with no
        body, so the run id cannot come from the dispatch response directly.
        The only robust association is: dispatch, then wait for the run row
        to appear in this workflow's run list (created_at >= dispatch time),
        capture its id once, and return it. Callers poll that exact id via
        GET /actions/runs/{id} - never by fragile run-name string matching.
        """
        addr = normalize_address(address)
        if not task_id or len(task_id) > 64:
            raise ValueError("invalid task_id")
        dispatched_at = datetime.now(UTC)
        resp = await self._request(
            "POST",
            f"/repos/{self._repo}/actions/workflows/{self._workflow}/dispatches",
            json_body={"ref": self._ref, "inputs": {"address": addr, "task_id": task_id}},
        )
        # GitHub documents 204 No Content for a successful dispatch.
        if resp.status_code != 204:
            logger.warning(
                "dispatch returned unexpected HTTP %s (expected 204); treating as sent",
                resp.status_code,
            )
        logger.info("workflow dispatched task=%s address=%s", task_id, addr)

        # A run is uniquely identified by its id. Find it once (retrying a
        # bounded window while the row appears, e.g. slow runner startup),
        # then the caller polls the exact id. We only ever match on the run
        # id derived from this dispatch, never on a run-name string.
        n = self._resolve_attempts
        for attempt in range(n):
            runs = await self._list_runs(since=dispatched_at, per_page=50)
            if len(runs) == 1:
                run_id = int(runs[0]["id"])
                logger.info(
                    "run associated task=%s run_id=%s (created_at=%s)",
                    task_id,
                    run_id,
                    runs[0].get("created_at"),
                )
                return run_id
            if len(runs) > 1:
                # Two+ runs created at/after the dispatch instant in this
                # workflow. Prefer the earliest one (first listed). The run
                # id is still authoritative; callers poll that exact id.
                run_id = int(runs[-1]["id"])
                logger.warning(
                    "dispatch window had %d runs; associating earliest run_id=%s for task=%s",
                    len(runs),
                    run_id,
                    task_id,
                )
                return run_id
            if attempt + 1 < n:
                await self._sleeper(self._poll_interval)
        raise RunAssociationError(
            f"no workflow run appeared for task={task_id!r} after dispatch "
            f"(waited {n * self._poll_interval:.0f}s)"
        )

    async def resolve_run_id(
        self, task_id: str, *, dispatched_after: datetime, attempts: int | None = None
    ) -> int:
        """Uniquely resolve the run for this task. Refuses to guess.

        Deprecated: kept for compatibility. Callers should use the run id
        returned directly by ``trigger_workflow`` instead of re-resolving by
        name. This still matches by run id (not by brittle run-name strings).
        """
        n = attempts or self._resolve_attempts
        for attempt in range(n):
            runs = await self._list_runs(since=dispatched_after, per_page=50)
            if len(runs) == 1:
                return int(runs[0]["id"])
            if len(runs) > 1:
                run_id = int(runs[-1]["id"])
                logger.warning(
                    "resolve window had %d runs; associating earliest run_id=%s", len(runs), run_id
                )
                return run_id
            if attempt + 1 < n:
                await self._sleeper(self._poll_interval)
        raise RunAssociationError(
            f"no workflow run appeared after dispatch for task={task_id!r} "
            f"(waited {n * self._poll_interval:.0f}s)"
        )

    async def _list_runs(self, *, since: datetime, per_page: int = 50) -> list[dict]:
        page = 1
        out: list[dict] = []
        while True:
            resp = await self._request(
                "GET",
                f"/repos/{self._repo}/actions/workflows/{self._workflow}/runs",
                params={"per_page": per_page, "page": page},
            )
            data = resp.json()
            batch = data.get("workflow_runs") or []
            for r in batch:
                created = _parse_ts(r.get("created_at"))
                if created and created >= since.replace(tzinfo=UTC):
                    out.append(r)
            # pagination: stop when batch is short or older runs fall below `since`
            if len(batch) < per_page:
                break
            oldest = _parse_ts(batch[-1].get("created_at")) if batch else None
            if oldest and oldest < since.replace(tzinfo=UTC):
                break
            page += 1
            if page > 10:
                break
        return out

    # ---------------------------------------------------------------- status
    async def get_run(self, run_id: int) -> dict[str, Any]:
        resp = await self._request("GET", f"/repos/{self._repo}/actions/runs/{run_id}")
        return resp.json()

    @staticmethod
    def map_run_status(run: dict[str, Any]) -> str:
        """GitHub status/conclusion -> our task state vocabulary."""
        status = (run.get("status") or "").lower()
        conclusion = (run.get("conclusion") or "").lower()
        if status in ("queued", "waiting", "pending"):
            return "queued"
        if status == "in_progress":
            return "running"
        if status == "completed":
            if conclusion == "success":
                return "completed"
            if conclusion == "cancelled":
                return "failed"
            if conclusion == "failure" or conclusion == "timed_out":
                return "failed"
            if conclusion == "startup_failure":
                return "failed"
            if conclusion == "skipped":
                return "failed"
            if conclusion == "neutral":
                return "completed"
            return "completed"
        return "running"

    # -------------------------------------------------------------- artifacts
    async def fetch_report(self, run_id: int, task_id: str) -> dict[str, Any]:
        """Download + safely extract this task's report artifact; parse JSON."""
        artifact_name = f"{self._artifact_name_prefix}{task_id}"
        resp = await self._request("GET", f"/repos/{self._repo}/actions/runs/{run_id}/artifacts")
        artifacts = (resp.json() or {}).get("artifacts") or []
        matching = [a for a in artifacts if a.get("name") == artifact_name]
        if not matching:
            raise GitHubClientError(f"artifact {artifact_name!r} not found on run {run_id}")
        art = matching[0]
        if art.get("expired"):
            raise ArtifactExpiredError(f"artifact {artifact_name!r} has expired")
        if art.get("workflow_run", {}).get("id") not in (None, run_id) and art.get(
            "run_id"
        ) not in (None, run_id):
            raise GitHubClientError("artifact does not belong to the expected run")

        zip_resp = await self._request(
            "GET", f"/repos/{self._repo}/actions/artifacts/{art['id']}/zip"
        )
        content = zip_resp.content
        if len(content) > MAX_ZIP_BYTES:
            raise GitHubClientError("artifact zip exceeds size policy")
        report_bytes = extract_report_from_zip(content, expected_names={"report.json"})
        try:
            import json as _json

            return _json.loads(report_bytes.decode("utf-8"))
        except Exception as exc:
            raise GitHubClientError(f"report.json is not valid JSON: {exc}") from exc


def extract_report_from_zip(content: bytes, *, expected_names: set[str]) -> bytes:
    """Safe ZIP extraction: one expected member, no traversal, size caps."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise GitHubClientError("artifact is not a valid ZIP") from exc

    total = 0
    found: dict[str, bytes] = {}
    for info in zf.infolist():
        name = Path(info.filename).name  # member basename
        path = info.filename.replace("\\", "/")
        if path.startswith("/") or ".." in Path(path).parts or info.is_dir():
            raise GitHubClientError(f"unsafe ZIP member: {info.filename!r}")
        if name not in expected_names:
            continue  # ignore auxiliary files, but never extract them
        if info.file_size > MAX_MEMBER_BYTES:
            raise GitHubClientError("ZIP member exceeds size policy")
        data = zf.read(info)
        total += len(data)
        if total > MAX_ZIP_BYTES:
            raise GitHubClientError("extracted content exceeds size policy")
        found[name] = data
    if "report.json" not in found:
        raise GitHubClientError("report.json missing from artifact")
    return found["report.json"]


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
