"""Email delivery helpers for authentication flows."""

from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage
import logging
import smtplib

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
    settings = get_settings()

    subject = settings.auth_email_mfa_subject
    from_email = settings.auth_email_mfa_from

    body = (
        "Use the verification code below to finish signing in:\n\n"
        f"{code}\n\n"
        f"This code expires at {_format_expiry(expires_at)}.\n"
    )
    if settings.auth_email_mfa_base_url:
        body += f"\nReturn to {settings.auth_email_mfa_base_url} to complete sign-in.\n"

    if settings.auth_email_mfa_delivery == "log":
        logger.info("Login code for %s: %s (expires %s)", to_email, code, _format_expiry(expires_at))
        return

    if settings.auth_email_mfa_delivery != "smtp":
        raise RuntimeError(f"Unsupported email delivery mode: {settings.auth_email_mfa_delivery}")

    if not settings.smtp_host:
        raise RuntimeError("SMTP host is not configured")

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if settings.smtp_use_ssl:
            smtp = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10)
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10)
        with smtp:
            if settings.smtp_use_tls and not settings.smtp_use_ssl:
                smtp.starttls()
            if settings.smtp_user and settings.smtp_password:
                smtp.login(settings.smtp_user, settings.smtp_password)
            smtp.send_message(msg)
    except Exception:
        logger.exception("Failed to send login code email")
        raise
