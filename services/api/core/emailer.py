"""Email delivery helpers for authentication flows."""

from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage
import logging
import smtplib

from core.config import get_config
from core.settings import get_settings

logger = logging.getLogger(__name__)


def _format_expiry(expires_at: datetime) -> str:
    """Return a human-readable UTC expiry timestamp."""
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expires_at = expires_at.astimezone(timezone.utc)
    return expires_at.strftime("%Y-%m-%d %H:%M UTC")


def send_login_code_email(*, to_email: str, code: str, expires_at: datetime) -> None:
    """Send a login verification code email."""
    email_cfg = get_config().email
    settings = get_settings()

    subject = email_cfg.subject
    from_email = email_cfg.from_address

    body = (
        "Use the verification code below to finish signing in:\n\n"
        f"{code}\n\n"
        f"This code expires at {_format_expiry(expires_at)}.\n"
    )
    if email_cfg.base_url:
        body += f"\nReturn to {email_cfg.base_url} to complete sign-in.\n"

    if email_cfg.delivery == "log":
        logger.info("Login code for %s: %s (expires %s)", to_email, code, _format_expiry(expires_at))
        return

    if email_cfg.delivery != "smtp":
        raise RuntimeError(f"Unsupported email delivery mode: {email_cfg.delivery}")

    if not email_cfg.smtp_host:
        raise RuntimeError("SMTP host is not configured")

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if email_cfg.smtp_use_ssl:
            smtp = smtplib.SMTP_SSL(email_cfg.smtp_host, email_cfg.smtp_port, timeout=10)
        else:
            smtp = smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port, timeout=10)
        with smtp:
            if email_cfg.smtp_use_tls and not email_cfg.smtp_use_ssl:
                smtp.starttls()
            if settings.smtp_user and settings.smtp_password:
                logger.info("Attempting SMTP login for user: %s", settings.smtp_user)
                smtp.login(settings.smtp_user, settings.smtp_password)
            else:
                logger.warning("Skipping SMTP login: SMTP_USER or SMTP_PASSWORD is not set")
            smtp.send_message(msg)
    except Exception:
        logger.exception("Failed to send login code email")
        raise
