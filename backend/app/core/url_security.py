from __future__ import annotations

import ipaddress
import socket
from fnmatch import fnmatch
from urllib.parse import urlparse

from fastapi import status
from pydantic import HttpUrl

from app.core.config import settings
from app.core.exceptions import AppError


BLOCKED_HOST_LABELS = {"localhost", "local", "metadata.google.internal"}
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal")
CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
}


def normalize_target_url(value: object) -> str:
    parsed = _parse_url(value)
    _validate_parsed_url(parsed)
    return parsed.geturl().rstrip("/")


def assert_safe_target_url(value: object) -> None:
    parsed = _parse_url(value)
    _validate_parsed_url(parsed)


def _parse_url(value: object):
    raw_url = str(value)
    if isinstance(value, HttpUrl):
        raw_url = str(value)
    parsed = urlparse(raw_url)
    if not parsed.scheme or not parsed.netloc:
        raise AppError("API base URL must be an absolute HTTP(S) URL", status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid_target_url")
    return parsed


def _validate_parsed_url(parsed) -> None:
    if parsed.scheme not in {"http", "https"}:
        raise AppError("Only HTTP and HTTPS API base URLs are supported", status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid_target_scheme")
    if parsed.username or parsed.password:
        raise AppError("API base URL must not include credentials", status.HTTP_422_UNPROCESSABLE_ENTITY, "target_url_credentials")
    if parsed.fragment:
        raise AppError("API base URL must not include a fragment", status.HTTP_422_UNPROCESSABLE_ENTITY, "target_url_fragment")
    if parsed.hostname is None:
        raise AppError("API base URL must include a host", status.HTTP_422_UNPROCESSABLE_ENTITY, "target_url_host_required")

    host = parsed.hostname.rstrip(".").lower()
    _enforce_host_allowlist(host)
    _enforce_host_blocklist(host)
    _reject_unsafe_hostname(host)
    _reject_unsafe_ip_literal(host)
    if settings.scanner_resolve_dns_for_ssrf:
        _reject_unsafe_dns_resolution(host)


def _enforce_host_allowlist(host: str) -> None:
    allowed = settings.scanner_allowed_host_patterns
    if allowed and not any(_host_matches(host, pattern) for pattern in allowed):
        raise AppError("API base URL host is not in the scanner allowlist", status.HTTP_400_BAD_REQUEST, "target_host_not_allowed")


def _enforce_host_blocklist(host: str) -> None:
    blocked = settings.scanner_blocked_host_patterns
    if any(_host_matches(host, pattern) for pattern in blocked):
        raise AppError("API base URL host is blocked by scanner policy", status.HTTP_400_BAD_REQUEST, "target_host_blocked")


def _host_matches(host: str, pattern: str) -> bool:
    normalized = pattern.strip().lower().rstrip(".")
    return bool(normalized) and fnmatch(host, normalized)


def _reject_unsafe_hostname(host: str) -> None:
    if host in BLOCKED_HOST_LABELS or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise AppError("Local or internal hostnames are blocked by scanner policy", status.HTTP_400_BAD_REQUEST, "target_host_internal")


def _reject_unsafe_ip_literal(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return
    _reject_unsafe_ip(ip)


def _reject_unsafe_dns_resolution(host: str) -> None:
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AppError("Unable to verify target host resolution", status.HTTP_400_BAD_REQUEST, "target_dns_unverified") from exc
    for result in results:
        ip = ipaddress.ip_address(result[4][0])
        _reject_unsafe_ip(ip)


def _reject_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if settings.scanner_allow_private_networks:
        return
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip in CLOUD_METADATA_IPS
    ):
        raise AppError("Private, local, reserved, and metadata network targets are blocked", status.HTTP_400_BAD_REQUEST, "target_ip_blocked")
