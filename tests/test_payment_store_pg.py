"""Postgres payment store integration tests (PROMPT 5).

These exercise the REAL Postgres-backed payments table: atomic replay
protection (UNIQUE payload_ref), concurrent submissions, state transitions,
single-credit transaction guard, and reconciliation of an on-chain settlement
whose follow-up write failed.

They require a Postgres database. Set PAYMENT_TEST_DATABASE_URL to point at a
throwaway schema/database (NOT production)::

    PAYMENT_TEST_DATABASE_URL=postgresql://... pytest -m pg

Without it the module skips. The migration creates only the AgentSafe
task/payment tables (tasks, task_stages, payments) - knowledge_* tables are
never touched.
"""

from __future__ import annotations

import os
import threading
from datetime import UTC, datetime

import pytest

PG_DSN = os.environ.get("PAYMENT_TEST_DATABASE_URL", "").strip()
pytestmark = [pytest.mark.pg]
requires_pg = pytest.mark.skipif(not PG_DSN, reason="PAYMENT_TEST_DATABASE_URL not set")


def _store():
    from agentsafe.task_store import PostgresTaskStore

    store = PostgresTaskStore(PG_DSN, retention_days=2)
    # Isolate: clear AgentSafe-owned rows only (never knowledge_*).
    with store._connect() as conn:
        conn.execute("TRUNCATE payments, task_stages, tasks")
    return store


@requires_pg
class TestReplayProtection:
    def test_reserve_is_atomic_and_once(self):
        store = _store()
        args = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        first = store.reserve_payment("ref-one", **args)
        assert first is not None and first["status"] == "verified"
        second = store.reserve_payment("ref-one", **args)
        assert second is None, "same payload_ref must never be reserved twice"

    def test_duplicate_audit_prevented_by_task_link(self):
        store = _store()
        args = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        row = store.reserve_payment("ref-task-link", **args)
        assert row is not None
        task = store.create_task("0x" + "11" * 20)
        store.link_payment_task(row["payment_id"], task.task_id)
        # A retry of the same payload finds the existing payment; the caller
        # can return the SAME task instead of dispatching a second audit.
        existing = store.get_payment_by_ref("ref-task-link")
        assert existing["task_id"] == task.task_id

    def test_concurrent_submissions_exactly_one_wins(self):
        """Concurrent reserve of the same payload_ref: the UNIQUE constraint
        must let exactly one insert succeed - no double-consume even when
        several requests race."""
        store = _store()
        args = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        results: list = []
        lock = threading.Lock()

        def _race():
            ok = store.reserve_payment("ref-race", **args)
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=_race) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wins = [r for r in results if r is not None]
        assert len(wins) == 1, f"exactly one winner expected, got {len(wins)}"


@requires_pg
class TestStateMachine:
    def test_legal_flow_and_terminal(self):
        store = _store()
        args = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        row = store.reserve_payment("ref-flow", **args)
        pid = row["payment_id"]
        store.transition_payment(pid, "resource_processing")
        store.transition_payment(pid, "settlement_pending")
        store.record_settlement(pid, success=True, transaction_hash="0x" + "aa" * 32)
        assert store.get_payment(pid)["status"] == "settled"
        store.transition_payment(pid, "completed")
        assert store.get_payment(pid)["status"] == "completed"

    def test_illegal_transition_raises(self):
        from agentsafe.payment.states import InvalidPaymentTransition

        store = _store()
        args = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        row = store.reserve_payment("ref-illegal", **args)
        pid = row["payment_id"]
        with pytest.raises(InvalidPaymentTransition):
            store.transition_payment(pid, "settled")  # verified -> settled illegal

    def test_transaction_credited_once(self):
        """A transaction hash may be recorded for at most one payment (the
        UNIQUE index prevents crediting one on-chain tx to two services)."""
        store = _store()
        tx = "0x" + "bb" * 32
        base = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        a = store.reserve_payment("ref-tx-a", **base)
        b = store.reserve_payment("ref-tx-b", **base)
        store.transition_payment(a["payment_id"], "resource_processing")
        store.transition_payment(a["payment_id"], "settlement_pending")
        store.record_settlement(a["payment_id"], success=True, transaction_hash=tx)
        store.transition_payment(b["payment_id"], "resource_processing")
        store.transition_payment(b["payment_id"], "settlement_pending")
        with pytest.raises(Exception):
            store.record_settlement(b["payment_id"], success=True, transaction_hash=tx)


@requires_pg
class TestReconciliation:
    def test_pending_with_tx_reconciles_to_settled(self):
        """Simulate 'settlement confirmed on-chain, follow-up DB write
        interrupted': the row stays SETTLEMENT_PENDING with a transaction
        hash; reconcile moves it to SETTLED idempotently."""
        store = _store()
        base = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        row = store.reserve_payment("ref-recon", **base)
        pid = row["payment_id"]
        store.transition_payment(pid, "resource_processing")
        store.transition_payment(pid, "settlement_pending")
        # Simulate the interrupted write: tx recorded, status still pending.
        with store._connect() as conn:
            conn.execute(
                "UPDATE payments SET transaction_hash = %s WHERE payment_id = %s",
                ("0x" + "cc" * 32, pid),
            )
        reconciled = store.reconcile_pending_settlements()
        assert pid in reconciled
        assert store.get_payment(pid)["status"] == "settled"
        # Idempotent: a second run finds nothing left.
        assert store.reconcile_pending_settlements() == []

    def test_ambiguous_rows_are_surfacable(self):
        store = _store()
        base = dict(network="eip155:84532", chain_id=84532,
                    token_contract="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                    token_decimals=6, amount="100", recipient="0x" + "ab" * 20)
        store.reserve_payment("ref-ambig", **base)
        rows = store.ambiguous_payments(older_than_minutes=0)
        assert any(r["payload_ref"] == "ref-ambig" for r in rows)
