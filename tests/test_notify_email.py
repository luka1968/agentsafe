"""Report-delivery email notification tests.

Covers:
  * email validation (pragmatic, bounded)
  * notifier disabled when SMTP_HOST unset (no-op, False)
  * successful send via mocked SMTP (subject/to/attachment)
  * SMTP failure never raises (False + logged)
  * task stores persist email + notified_at (Memory + SQLite)
  * single-send semantics: mark_notified once, notified_at set
"""

import os
from datetime import UTC, datetime
from email.message import EmailMessage
from unittest import mock

import pytest

from agentsafe import notify
from agentsafe.notify import is_valid_email, send_report_ready_email
from agentsafe.task_store import MemoryTaskStore, SqliteTaskStore

BASE = "https://x402.workfern.com"
TASK = "abc123def4567890"


class TestEmailValidation:
    def test_valid_addresses(self):
        for e in ("a@b.co", "user.name+tag@example.com", "x@sub.domain.io"):
            assert is_valid_email(e), e

    def test_invalid_addresses(self):
        for e in (None, "", "  ", "no-at-sign", "a@b", "a@.com", "a@com.",
                  "a b@c.com", "x" * 250 + "@b.co"):
            assert not is_valid_email(e), e


class TestNotifierDisabled:
    def test_disabled_without_smtp_host(self, monkeypatch):
        monkeypatch.delenv("SMTP_HOST", raising=False)
        assert notify.notify_enabled() is False
        assert send_report_ready_email("a@b.co", TASK, BASE) is False

    def test_invalid_recipient_never_sends(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.test")
        with mock.patch.object(notify.smtplib, "SMTP") as smtp:
            assert send_report_ready_email("not-an-email", TASK, BASE) is False
            smtp.assert_not_called()


class TestSendSuccess:
    def _run(self, *, with_md: bool) -> EmailMessage:
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                sent["host"], sent["port"] = host, port

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def ehlo(self):
                pass

            def starttls(self, context=None):
                sent["tls"] = True

            def login(self, u, p):
                sent["login"] = (u, p)

            def send_message(self, msg):
                sent["msg"] = msg

        env = {"SMTP_HOST": "smtp.test", "SMTP_PORT": "587",
               "SMTP_USER": "bot@test", "SMTP_PASS": "pw",
               "NOTIFY_FROM": "AgentSafe <reports@test>"}
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(notify.smtplib, "SMTP", FakeSMTP):
            md = "# report\nfindings..." if with_md else None
            ok = send_report_ready_email("cust@example.com", TASK, BASE,
                                         report_markdown=md)
            assert ok is True
            # capture the message object content
            sent["msg2"] = sent.get("msg")
        return sent

    def test_sends_with_links(self):
        sent = self._run(with_md=False)
        msg = sent["msg2"]
        assert msg["To"] == "cust@example.com"
        assert msg["From"] == "AgentSafe <reports@test>"
        assert TASK[:8] in msg["Subject"]          # short id in subject
        body = msg.get_content()
        assert f"{BASE}/api/audit/{TASK}/report.md" in body
        assert TASK in body                        # full id in body

    def test_attach_markdown_when_provided(self):
        sent = self._run(with_md=True)
        msg = sent["msg2"]
        attachments = [p for p in msg.iter_attachments()]
        assert len(attachments) == 1
        assert attachments[0].get_filename() == f"agentsafe-{TASK}.md"

    def test_smtp_failure_returns_false_never_raises(self, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "smtp.test")
        with mock.patch.object(notify.smtplib, "SMTP",
                               side_effect=OSError("connection refused")):
            assert send_report_ready_email("a@b.co", TASK, BASE) is False


class TestTaskStoreEmail:
    def test_memory_store_email_roundtrip(self):
        store = MemoryTaskStore()
        t = store.create_task("0x" + "a" * 40, email="c@e.co")
        got = store.get(t.task_id)
        assert got.email == "c@e.co"
        assert got.notified_at is None
        store.mark_notified(t.task_id)
        got = store.get(t.task_id)
        assert got.notified_at is not None
        # single-send semantics: notified_at set once, idempotent
        first = got.notified_at
        store.mark_notified(t.task_id)
        assert store.get(t.task_id).notified_at is not None

    def test_sqlite_store_email_roundtrip(self, tmp_path):
        store = SqliteTaskStore(tmp_path / "tasks.db")
        t = store.create_task("0x" + "b" * 40, email="d@e.co")
        got = store.get(t.task_id)
        assert got.email == "d@e.co"
        assert got.notified_at is None
        store.mark_notified(t.task_id)
        got = store.get(t.task_id)
        assert got.notified_at is not None
        # legacy DBs without the column: migrate() adds it on open
        store2 = SqliteTaskStore(tmp_path / "tasks.db")
        assert store2.get(t.task_id).email == "d@e.co"

    def test_email_optional_backward_compatible(self, tmp_path):
        """create_task without email keeps working (existing callers)."""
        store = SqliteTaskStore(tmp_path / "t2.db")
        t = store.create_task("0x" + "c" * 40)
        assert store.get(t.task_id).email is None


class TestSingleSendGuard:
    def test_notify_helper_respects_notified_at(self, monkeypatch):
        """_maybe_notify_report_ready sends once: a notified task is skipped."""
        from agentsafe.server import _maybe_notify_report_ready

        store = MemoryTaskStore()
        t = store.create_task("0x" + "d" * 40, email="z@e.co")
        sent = {"n": 0}

        def fake_send(to, task_id, base, report_markdown=None):
            sent["n"] += 1
            return True

        monkeypatch.setattr(notify, "send_report_ready_email", fake_send)
        _maybe_notify_report_ready(store, t.task_id, BASE)
        assert sent["n"] == 1
        assert store.get(t.task_id).notified_at is not None
        # second probe (customer refreshes page) -> no duplicate email
        _maybe_notify_report_ready(store, t.task_id, BASE)
        assert sent["n"] == 1

    def test_notify_helper_skips_tasks_without_email(self, monkeypatch):
        from agentsafe.server import _maybe_notify_report_ready

        store = MemoryTaskStore()
        t = store.create_task("0x" + "e" * 40)  # no email
        sent = {"n": 0}
        monkeypatch.setattr(notify, "send_report_ready_email",
                            lambda *a, **k: sent.__setitem__("n", sent["n"] + 1) or True)
        _maybe_notify_report_ready(store, t.task_id, BASE)
        assert sent["n"] == 0