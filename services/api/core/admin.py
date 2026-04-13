from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Iterable
from urllib.parse import urlparse
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.auth import AuthenticatedUser, get_authenticated_user
from core.settings import get_settings


def _is_loopback_host(host: str | None) -> bool:
    """Return True when the host resolves to a loopback address."""
    if host is None:
        return False

    normalized = host.strip().lower()
    if normalized == "localhost":
        return True

    try:
        parsed = ip_address(normalized)
    except ValueError:
        return False

    if parsed.is_loopback:
        return True

    ipv4_mapped = getattr(parsed, "ipv4_mapped", None)
    return bool(ipv4_mapped and ipv4_mapped.is_loopback)


def _hosts_match(left: str, right: str) -> bool:
    """Normalize and compare hostnames or IP literals."""
    left_normalized = left.strip().lower()
    right_normalized = right.strip().lower()
    if left_normalized == "*" or right_normalized == "*":
        return True
    if left_normalized == right_normalized:
        return True

    try:
        return ip_address(left_normalized) == ip_address(right_normalized)
    except ValueError:
        return False


def _is_from_trusted_proxy(host: str | None, trusted_proxy_hosts: Iterable[str]) -> bool:
    """Return True when the direct client matches a configured proxy host or CIDR range."""
    if host is None:
        return False
    normalized = host.strip().lower()
    for trusted in trusted_proxy_hosts:
        if _hosts_match(normalized, trusted):
            return True
        try:
            if ip_address(normalized) in ip_network(trusted.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_in_allowed_hosts(host: str | None, allowed_hosts: Iterable[str]) -> bool:
    """Return True when the host matches a configured allowlist entry."""
    if host is None:
        return False
    return any(_hosts_match(host, allowed) for allowed in allowed_hosts)


def _is_in_allowed_networks(host: str | None, allowed_networks: Iterable[str]) -> bool:
    """Return True when the host belongs to an allowed CIDR range."""
    if host is None:
        return False
    normalized = host.strip().lower()
    try:
        host_ip = ip_address(normalized)
    except ValueError:
        return False

    for network in allowed_networks:
        try:
            if host_ip in ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False


def _get_effective_client_host(request: Request) -> str | None:
    """Derive the true client host, honoring trusted proxy headers."""
    settings = get_settings()
    direct_host = request.client.host if request.client is not None else None
    # Only trust X-Forwarded-For when the immediate peer is a known proxy.
    if not _is_from_trusted_proxy(direct_host, settings.admin_trusted_proxy_hosts):
        return direct_host

    forwarded_for = request.headers.get(settings.admin_forwarded_for_header)
    if not forwarded_for:
        return direct_host

    first_forwarded_host = forwarded_for.split(",")[0].strip()
    if first_forwarded_host:
        return first_forwarded_host
    return direct_host


def require_localhost_request(request: Request) -> None:
    """Enforce localhost-only admin access unless allowlists override it."""
    settings = get_settings()
    if not settings.admin_localhost_only:
        return

    client_host = _get_effective_client_host(request)
    if _is_loopback_host(client_host):
        return
    if _is_in_allowed_hosts(client_host, settings.admin_allowed_hosts):
        return
    if _is_in_allowed_networks(client_host, settings.admin_allowed_networks):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin endpoints are only available from localhost",
    )


def require_admin_user(
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
) -> AuthenticatedUser:
    """Require that the authenticated user has admin privileges."""
    if current_user.is_admin:
        return current_user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin privileges required",
    )


def _hash_token(token: str) -> str:
    """Hash a token for storage and comparison."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_admin_origin(request: Request, *, require_present: bool = True) -> None:
    """Ensure Origin/Referer points to localhost (and is present if required)."""
    settings = get_settings()
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    def _origin_host(value: str) -> str | None:
        try:
            parsed = urlparse(value)
            return parsed.hostname
        except Exception:
            return None

    if require_present and not origin and not referer:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin actions require a localhost browser origin",
        )

    if origin:
        origin_host = _origin_host(origin)
        if not _is_loopback_host(origin_host) and not _is_in_allowed_hosts(
            origin_host, settings.admin_allowed_hosts
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin actions require localhost or allowed origin",
            )

    if referer:
        referer_host = _origin_host(referer)
        if not _is_loopback_host(referer_host) and not _is_in_allowed_hosts(
            referer_host, settings.admin_allowed_hosts
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin actions require localhost or allowed origin",
            )


def issue_admin_action_token(
    db: Session,
    *,
    session_id: str,
) -> tuple[str, datetime]:
    """Generate and persist a short-lived admin action token."""
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.admin_action_token_ttl_minutes
    )

    db.execute(
        text(
            """
            DELETE FROM admin_action_tokens
            WHERE session_id = :session_id
            """
        ),
        {"session_id": session_id},
    )

    db.execute(
        text(
            """
            INSERT INTO admin_action_tokens (session_id, token_hash, expires_at)
            VALUES (:session_id, :token_hash, :expires_at)
            """
        ),
        {
            "session_id": session_id,
            "token_hash": token_hash,
            "expires_at": expires_at,
        },
    )

    db.commit()
    return token, expires_at


def require_admin_action_token(
    request: Request,
    *,
    db: Session,
    session_id: str,
) -> str:
    """Validate the admin action token against the session."""
    token = request.headers.get("x-admin-action")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin action token required",
        )

    token_hash = _hash_token(token)
    row = db.execute(
        text(
            """
            SELECT expires_at
            FROM admin_action_tokens
            WHERE session_id = :session_id
              AND token_hash = :token_hash
            """
        ),
        {"session_id": session_id, "token_hash": token_hash},
    ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid admin action token",
        )

    expires_at = row[0]
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin action token expired",
        )
    return token


def consume_admin_action_token(
    db: Session,
    *,
    session_id: str,
    token: str,
) -> None:
    """Consume an admin action token after use."""
    token_hash = _hash_token(token)
    db.execute(
        text(
            """
            DELETE FROM admin_action_tokens
            WHERE session_id = :session_id
              AND token_hash = :token_hash
            """
        ),
        {"session_id": session_id, "token_hash": token_hash},
    )
