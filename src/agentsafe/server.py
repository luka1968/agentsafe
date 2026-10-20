"""FastMCP server - the agentSAFE MCP entry point.

Tools:
  audit_contract(address)        -> dispatch GitHub Actions audit, return task_id
  check_audit_status(task_id)   -> recoverable status + report when ready
  get_contract_info(address)    -> on-chain + verification snapshot

Modes:
  stdio  : local development / single-client (default)
  http   : remote deployment (run behind an authenticating proxy)

Payments: fail-closed x402 gate (Phase 12). PAYMENTS_ENABLED=false runs free
in dev mode; true requires the pinned official x402 SDK (see
payment/x402_adapter.py) and gates audit_contract with verify-before-execution
/ settle-after-execution. Report retrieval is bound to the verified payment.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.tools import ToolResult

from agentsafe import __version__
from agentsafe.config import Settings, validate_runtime_settings
from agentsafe.explorer import ContractNotVerifiedError, EtherscanClient
from agentsafe.github_client import (
    ArtifactExpiredError,
    GitHubActionsClient,
    GitHubClientError,
    RunAssociationError,
)
from agentsafe.payment.x402_adapter import (
    VerifiedPayment,
    X402PaymentAdapter,
)
from agentsafe.rpc import EthRpcClient
from agentsafe.schemas import AuditReport, TaskState, normalize_address
from agentsafe.task_store import open_task_store

logger = logging.getLogger("agentSAFE.server")

mcp: FastMCP | None = None


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    # httpx logs full request URLs at INFO; Etherscan URLs embed the API key
    # as a query parameter, so those lines must never be emitted.
    logging.getLogger("httpx").setLevel(logging.WARNING)


def build_server(settings: Settings, *, validate: bool = True) -> FastMCP:
    """Construct the FastMCP instance. Fails fast on bad config.

    validate=False defers configuration validation to server startup via a
    lifespan hook. Used for cloud deployments (FastMCP Cloud / Horizon)
    where build-time inspection runs without environment variables; a
    misconfigured deployment still refuses to serve at runtime.
    """
    if validate:
        validate_runtime_settings(settings)  # raises SettingsError with ALL problems

    task_store = open_task_store(
        getattr(settings, "TASK_STORE", "sqlite"),
        Path(getattr(settings, "TASK_DB_PATH", "data/tasks.db")),
        retention_days=settings.ARTIFACT_RETENTION_DAYS,
    )

    # Payments gate (fail-closed; disabled = dev no-op)
    payment = X402PaymentAdapter(
        enabled=settings.PAYMENTS_ENABLED,
        sdk_version=settings.X402_SDK_VERSION,
        network=settings.X402_NETWORK,
        pay_to=settings.X402_PAY_TO,
        facilitator_url=settings.X402_FACILITATOR_URL,
        price=settings.X402_PRICE,
        asset=settings.X402_ASSET,
        max_timeout_seconds=settings.X402_MAX_TIMEOUT_SECONDS,
    )

    gh = GitHubActionsClient(
        token=settings.GITHUB_TOKEN,
        repo=settings.GITHUB_REPO,
        workflow_file=settings.GITHUB_WORKFLOW_FILE,
        ref=settings.GITHUB_REF,
        timeout_seconds=settings.GITHUB_API_TIMEOUT_SECONDS,
        poll_interval_seconds=settings.GITHUB_POLL_INTERVAL_SECONDS,
        strict=validate,
    )

    rpc = EthRpcClient(settings.INFURA_ETH_ENDPOINT)
    explorer = EtherscanClient(
        settings.ETHERSCAN_API_KEY,
        base_url=settings.ETHERSCAN_BASE_URL,
        strict=validate,
    )

    @asynccontextmanager
    async def _startup_validation(server: FastMCP) -> AsyncIterator[None]:
        if not validate:
            # Cloud mode: env vars only exist at runtime, so fail fast HERE.
            validate_runtime_settings(Settings())
        yield None

    app = FastMCP(
        "agentSAFE",
        instructions=(
            "EVM smart-contract audit MCP (Ethereum Mainnet). AI-assisted risk "
            "screening, NOT a formal security audit. Findings require human "
            "verification before any action."
        ),
        lifespan=_startup_validation,
        # Production safety: clients never receive internal stack traces or
        # environment-derived error details from a crashing tool; full
        # details stay in the service logs.
        mask_error_details=True,
    )

    @app.tool
    async def health() -> dict[str, Any]:
        """Liveness/config probe. Safe, non-paid, and never returns secrets.

        Use this to verify a deployment (public endpoint reachability,
        tool discovery) without triggering an audit or a payment.
        """
        return {
            "ok": True,
            "service": "agentSAFE",
            "version": __version__,
            "chain": "ethereum-mainnet",
            "payments": {
                "enabled": payment.enabled,
                "network": settings.X402_NETWORK if payment.enabled else None,
                "price": settings.X402_PRICE if payment.enabled else None,
            },
            "task_store": getattr(settings, "TASK_STORE", "sqlite"),
            "audit_workflow": settings.GITHUB_WORKFLOW_FILE,
            "terms_of_service": "https://github.com/luka1968/agentsafe/blob/main/TERMS_OF_SERVICE.md",
        }

    @app.tool
    async def audit_contract(address: str, ctx: Context) -> dict[str, Any] | ToolResult:
        """Start an audit for a Mainnet contract address. Returns a task_id.

        The audit runs on a GitHub Actions worker; poll check_audit_status.

        When payments are enabled, this tool is x402-gated: an unpaid call
        returns the official 402 payment-required body and never dispatches.
        """
        try:
            addr = normalize_address(address)
        except ValueError as exc:
            return {"ok": False, "error_code": "invalid_address", "error": str(exc)}

        verified: VerifiedPayment | None = None
        if payment.enabled:
            # Official SDK flow: verify BEFORE execution. Unverified requests
            # receive the payment-required result and no dispatch happens.
            verified, deny = await payment.verify(ctx, "audit_contract")
            if deny is not None:
                return deny

        task = task_store.create_task(addr)
        if verified is not None:
            # Bind the verified payment to this task; report retrieval for
            # this task is released only when this flag is set.
            task_store.mark_paid(task.task_id, verified.ref)
        task_store.set_state(task.task_id, TaskState.QUEUED)
        logger.info("audit_contract address=%s task_id=%s", addr, task.task_id)
        try:
            dispatched_at = await gh.trigger_workflow(addr, task.task_id)
            run_id = await gh.resolve_run_id(task.task_id, dispatched_after=dispatched_at)
            task_store.link_run(task.task_id, run_id)
            task_store.set_state(task.task_id, TaskState.RUNNING)
        except RunAssociationError as exc:
            settled = await _settle_payment(verified, "audit_contract")
            if settled is not None:
                return settled
            return {
                "ok": True,
                "task_id": task.task_id,
                "address": addr,
                "note": (
                    "workflow dispatched but run not yet visible; retry check_audit_status shortly"
                ),
                "detail": str(exc),
            }
        except GitHubClientError as exc:
            # Dispatch failed: settlement is NOT attempted (verify-only so far,
            # the on-chain transfer never executes -> no funds collected).
            # No refund is owed or promised.
            task_store.set_state(task.task_id, TaskState.FAILED, error_code="dispatch_failed")
            return {
                "ok": False,
                "task_id": task.task_id,
                "error_code": "dispatch_failed",
                "error": str(exc),
            }
        settled = await _settle_payment(verified, "audit_contract")
        if settled is not None:
            return settled
        return {
            "ok": True,
            "task_id": task.task_id,
            "address": addr,
            "run_id": run_id,
            "state": "running",
        }

    async def _settle_payment(
        verified: VerifiedPayment | None, tool_name: str
    ) -> ToolResult | None:
        """Settle AFTER successful execution (official after-handler phase).

        Returns the settlement-failed error result on failure, else None.
        A settlement failure does not stop the dispatched audit; it is
        surfaced to the payer. No automatic refunds exist in the exact-EVM
        scheme.
        """
        if verified is None:
            return None
        try:
            settle_result = await payment.settle(verified)
        except Exception as exc:
            logger.error("settlement failed tool=%s ref=%s: %s", tool_name, verified.ref, exc)
            return await payment.settlement_failed_result(tool_name, str(exc))
        if not settle_result.success:
            logger.error(
                "settlement rejected tool=%s ref=%s reason=%s",
                tool_name,
                verified.ref,
                settle_result.error_reason,
            )
            return await payment.settlement_failed_result(
                tool_name, settle_result.error_reason or "unknown settlement failure"
            )
        logger.info(
            "payment settled tool=%s ref=%s tx=%s",
            tool_name,
            verified.ref[:16],
            settle_result.transaction,
        )
        return None

    @app.tool
    async def check_audit_status(task_id: str) -> dict[str, Any]:
        """Check audit progress; returns the report once the run completes."""
        if not task_id or len(task_id) > 64:
            return {
                "ok": False,
                "error_code": "invalid_task_id",
                "error": "task_id must be 1..64 chars",
            }
        task = task_store.get(task_id)
        if task is None:
            return {
                "ok": False,
                "error_code": "unknown_task",
                "error": "no such task (it may have expired or never existed)",
            }

        if task.run_id is None:
            return {
                "ok": True,
                "task_id": task_id,
                "state": task.state.value,
                "detail": "workflow dispatch pending or run not yet associated",
            }

        try:
            run = await gh.get_run(task.run_id)
        except GitHubClientError as exc:
            return {
                "ok": True,
                "task_id": task_id,
                "state": task.state.value,
                "error": f"status lookup failed: {exc}",
            }

        mapped = gh.map_run_status(run)
        task_store.set_state(task_id, TaskState(mapped))

        if mapped == "completed":
            if payment.enabled and not task.paid:
                # Payment binding: a task that never passed payment
                # verification must not release a paid report.
                return {
                    "ok": False,
                    "task_id": task_id,
                    "state": mapped,
                    "error_code": "payment_required",
                    "error": "report withheld: no verified payment is bound to this task",
                }
            try:
                report = await gh.fetch_report(task.run_id, task_id)
            except ArtifactExpiredError:
                task_store.set_state(task_id, TaskState.EXPIRED, error_code="artifact_expired")
                return {
                    "ok": True,
                    "task_id": task_id,
                    "state": "expired",
                    "error": "report artifact expired; re-run the audit",
                }
            except GitHubClientError as exc:
                return {
                    "ok": True,
                    "task_id": task_id,
                    "state": mapped,
                    "error": f"report unavailable: {exc}",
                }
            task_store.set_state(task_id, TaskState.COMPLETED)
            return {
                "ok": True,
                "task_id": task_id,
                "state": "completed",
                "report": _clip_report(report),
            }
        if mapped == "failed":
            task_store.set_state(
                task_id, TaskState.FAILED, error_code=f"run_conclusion:{run.get('conclusion')}"
            )
        return {
            "ok": True,
            "task_id": task_id,
            "state": mapped,
            "run_conclusion": run.get("conclusion"),
        }

    @app.tool
    async def get_contract_info(address: str) -> dict[str, Any]:
        """On-chain snapshot: is contract, bytecode size, verified source?"""
        try:
            addr = normalize_address(address)
        except ValueError as exc:
            return {"ok": False, "error_code": "invalid_address", "error": str(exc)}
        info: dict[str, Any] = {"address": addr}
        try:
            code = await rpc.get_code(addr)
            info["is_contract"] = len(code) > 2
            info["bytecode_size_bytes"] = (len(code) - 2) // 2
        except Exception as exc:
            info["rpc_error"] = str(exc)
        try:
            await explorer.get_verified_source(addr)
            info["verified_source"] = True
        except ContractNotVerifiedError:
            info["verified_source"] = False
        except Exception as exc:
            info["etherscan_error"] = str(exc)
        return {"ok": True, **info}

    return app


def _clip_report(report: dict[str, Any]) -> dict[str, Any]:
    """Sanity-clip the report payload returned through MCP."""
    if not isinstance(report, dict):
        return {"raw": str(report)[:1000]}
    findings = report.get("findings")
    if isinstance(findings, list) and len(findings) > 100:
        report = dict(report)
        report["findings"] = findings[:100]
        report["findings_truncated"] = True
    try:
        AuditReport.model_validate(report)  # validate shape when possible
    except Exception:
        return {"raw": str(report)[:4000]}
    return report


def create_app() -> FastMCP:
    """Zero-arg factory for FastMCP Cloud / Prefect Horizon deployments.

    Entrypoint: agentsafe.server:create_app (env vars supply all settings).
    Cloud builds inspect the server WITHOUT env vars, so validation is
    deferred to runtime startup (see build_server validate=False).
    """
    return build_server(Settings(), validate=False)


def main() -> None:
    """Entry point: python -m agentsafe.server [--transport stdio|http]"""
    import argparse

    parser = argparse.ArgumentParser(description="agentSAFE MCP server")
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    settings = Settings()
    _setup_logging(settings.LOG_LEVEL)
    global mcp
    mcp = build_server(settings)
    logger.info(
        "agentSAFE MCP v%s starting (transport=%s, payments=%s)",
        __version__,
        args.transport,
        settings.PAYMENTS_ENABLED,
    )
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
