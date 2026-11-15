"""Report-delivery email notifier (optional, zero-dependency).

Configured entirely via environment variables:
    SMTP_HOST   e.g. smtp.gmail.com / smtp.resend.com (required to enable)
    SMTP_PORT   default 587 (STARTTLS)
    SMTP_USER   login (optional for relays that do not need auth)
    SMTP_PASS   password / API key
    NOTIFY_FROM From header, e.g. "AgentSafe <reports@yourdomain.com>"
                (defaults to SMTP_USER when unset)

Behavior:
  * SMTP_HOST unset/empty -> the notifier is DISABLED: every send is a no-op
    that logs once and returns False. The feature degrades cleanly - audits
    and reports work exactly as before.
  * send_report_ready_email never raises: any failure is logged and returned
    as False so the audit/report request path is never broken by mail.
  * One terminal-state email per task (report-ready OR audit-failed,
    whichever is detected first): the caller guards with
    TaskStatus.notified_at (task_store.mark_notified after a send).
"""

from __future__ import annotations

import logging
import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

logger = logging.getLogger("agentSAFE.notify")

_EMAIL_MAX = 254


def is_valid_email(raw: str | None) -> bool:
    """Pragmatic RFC-ish validation: one @, non-empty local part, domain with
    a dot, no whitespace, bounded length. Deliberately not a full RFC parser."""
    if not raw or len(raw) > _EMAIL_MAX:
        return False
    if raw != raw.strip() or any(c.isspace() for c in raw):
        return False
    local, sep, domain = raw.partition("@")
    return bool(
        sep and local and domain and "." in domain
        and not domain.startswith(".") and not domain.endswith(".")
        and " " not in domain
    )


@dataclass
class _SmtpConfig:
    host: str
    port: int
    user: str | None
    password: str | None
    sender: str


def _config() -> _SmtpConfig | None:
    host = (os.environ.get("SMTP_HOST") or "").strip()
    if not host:
        return None
    try:
        port = int((os.environ.get("SMTP_PORT") or "587").strip() or 587)
    except ValueError:
        port = 587
    user = (os.environ.get("SMTP_USER") or "").strip() or None
    password = os.environ.get("SMTP_PASS") or None
    sender = (os.environ.get("NOTIFY_FROM") or "").strip() \
        or (user or f"AgentSafe <reports@{host}>")
    return _SmtpConfig(host=host, port=port, user=user, password=password,
                       sender=sender)


def notify_enabled() -> bool:
    """True when SMTP is configured (feature on)."""
    return _config() is not None


REPORT_READY_SUBJECT = "AgentSafe audit report ready (task {short})"

REPORT_READY_BODY = """Your AgentSafe smart contract audit is complete.

Task ID: {task_id}

Report (all formats):
  Markdown: {base}/api/audit/{task_id}/report.md
  HTML:     {base}/api/audit/{task_id}/report
  JSON:     {base}/api/audit/{task_id}/report.json
  PDF:      {base}/api/audit/{task_id}/report.pdf

The report links remain valid while the report artifact is retained.
Keep this email - the task ID is your capability to fetch the report.

You are receiving this because you requested report delivery when
submitting the audit. No further emails will be sent for this task.
"""

AUDIT_FAILED_SUBJECT = "AgentSafe audit did not complete (task {short})"

AUDIT_FAILED_BODY = """Your AgentSafe smart contract audit did not complete.

Task ID: {task_id}

The audit workflow failed before producing a report{detail}.
No report files were generated for this task.

What happens next:
  * Your payment is preserved and the credit/refund policy applies:
    {base}/refund
  * To request a refund, contact support with this task ID
    (support address is listed on the refund page).
  * You can retry the audit at any time by submitting the contract again.

Keep this email - the task ID identifies your order for support.
You are receiving this because you requested report delivery when
submitting the audit. No further emails will be sent for this task.
"""


def _short(task_id: str) -> str:
    return task_id[:8] + "..." if len(task_id) > 8 else task_id


def _smtp_send(cfg: _SmtpConfig, msg: EmailMessage, task_id: str,
               to_email: str, kind: str) -> bool:
    try:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=15) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            except smtplib.SMTPNotSupportedError:
                pass  # implicit TLS relays (port 465 setups that allow it)
            if cfg.user and cfg.password:
                smtp.login(cfg.user, cfg.password)
            smtp.send_message(msg)
        logger.info("%s email sent task=%s to=%s", kind, task_id, to_email)
        return True
    except Exception:  # noqa: BLE001 - mail must never break the audit path
        logger.exception("%s email failed task=%s to=%s",
                         kind, task_id, to_email)
        return False


def send_report_ready_email(to_email: str, task_id: str, base_url: str,
                            report_markdown: str | None = None) -> bool:
    """Email the customer that the report is ready, with all report-format
    links and (when available) the markdown report attached. Returns True on
    success; False on any failure or when the notifier is disabled. Never
    raises into the caller's request path."""
    cfg = _config()
    if cfg is None:
        logger.info("email notify disabled (SMTP_HOST unset); skip task=%s",
                    task_id)
        return False
    if not is_valid_email(to_email):
        logger.warning("invalid recipient email; skip task=%s", task_id)
        return False
    base = (base_url or "").rstrip("/")
    msg = EmailMessage()
    msg["From"] = cfg.sender
    msg["To"] = to_email
    msg["Subject"] = REPORT_READY_SUBJECT.format(short=_short(task_id))
    msg.set_content(REPORT_READY_BODY.format(task_id=task_id, base=base))
    if report_markdown:
        msg.add_attachment(
            report_markdown.encode("utf-8"), maintype="text",
            subtype="markdown", filename=f"agentsafe-{task_id}.md")
    return _smtp_send(cfg, msg, task_id, to_email, "report-ready")


def send_audit_failed_email(to_email: str, task_id: str, base_url: str,
                            failure_detail: str | None = None) -> bool:
    """Email the customer that the audit failed and no report exists, with
    the refund-policy pointer and the task ID for support. Same contract as
    send_report_ready_email: True on success, never raises."""
    cfg = _config()
    if cfg is None:
        logger.info("email notify disabled (SMTP_HOST unset); skip task=%s",
                    task_id)
        return False
    if not is_valid_email(to_email):
        logger.warning("invalid recipient email; skip task=%s", task_id)
        return False
    base = (base_url or "").rstrip("/")
    detail = f" (run {failure_detail})" if failure_detail else ""
    msg = EmailMessage()
    msg["From"] = cfg.sender
    msg["To"] = to_email
    msg["Subject"] = AUDIT_FAILED_SUBJECT.format(short=_short(task_id))
    msg.set_content(AUDIT_FAILED_BODY.format(
        task_id=task_id, base=base, detail=detail))
    return _smtp_send(cfg, msg, task_id, to_email, "audit-failed")
