from __future__ import annotations

from ipaddress import ip_address
from typing import Iterable

from fastapi import Depends, HTTPException, Request, status

from core.auth import AuthenticatedUser, get_authenticated_user
from core.settings import get_settings


def _is_loopback_host(host: str | None) -> bool:
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
    left_normalized = left.strip().lower()
    right_normalized = right.strip().lower()
    if left_normalized == right_normalized:
        return True

    try:
        return ip_address(left_normalized) == ip_address(right_normalized)
    except ValueError:
        return False


def _is_from_trusted_proxy(host: str | None, trusted_proxy_hosts: Iterable[str]) -> bool:
    if host is None:
        return False
    return any(_hosts_match(host, trusted) for trusted in trusted_proxy_hosts)


def _get_effective_client_host(request: Request) -> str | None:
    settings = get_settings()
    direct_host = request.client.host if request.client is not None else None
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
    settings = get_settings()
    if not settings.admin_localhost_only:
        return

    client_host = _get_effective_client_host(request)
    if _is_loopback_host(client_host):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin endpoints are only available from localhost",
    )


def require_admin_user(
    current_user: AuthenticatedUser = Depends(get_authenticated_user),
) -> AuthenticatedUser:
    if current_user.is_admin:
        return current_user

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Admin privileges required",
    )
