import re
from urllib.parse import urlparse

from app.scanner.types import FindingDraft, ResponseSnapshot


RISK_BY_SEVERITY = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}
SUCCESS_STATUSES = {200, 201, 204}
MIN_HSTS_MAX_AGE_SECONDS = 15_552_000

SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(^|/)(admin|internal|manage|management|root)(/|$)", re.I),
    re.compile(r"(^|/)(user|users|account|accounts|profile|profiles|me)(/|$)", re.I),
    re.compile(r"(^|/)(payment|payments|billing|invoice|invoices|checkout|subscription)(/|$)", re.I),
    re.compile(r"(^|/)(customer|customers|tenant|tenants|member|members)(/|$)", re.I),
]


def check_security_headers(snapshot: ResponseSnapshot) -> list[FindingDraft]:
    headers = _headers_lower(snapshot.headers)
    findings: list[FindingDraft] = []

    findings.extend(_check_hsts(snapshot, headers))
    findings.extend(_check_csp(snapshot, headers))
    findings.extend(_check_x_content_type_options(snapshot, headers))
    findings.extend(_check_x_frame_options(snapshot, headers))
    findings.extend(_check_referrer_policy(snapshot, headers))
    findings.extend(_check_permissions_policy(snapshot, headers))
    findings.extend(_check_sensitive_cache_control(snapshot, headers))

    return findings


def _check_hsts(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    header = headers.get("strict-transport-security")
    if urlparse(snapshot.url).scheme.lower() != "https":
        return [
            _finding(
                snapshot,
                "Medium",
                "Strict-Transport-Security cannot be enforced over HTTP",
                "Endpoint URL is not HTTPS, so browsers cannot apply HSTS for this response.",
                "Serve production APIs over HTTPS and return Strict-Transport-Security with a long max-age from HTTPS responses.",
            )
        ]
    if not header:
        return [
            _finding(
                snapshot,
                "Medium",
                "Strict-Transport-Security header is missing",
                "Strict-Transport-Security was not present on an HTTPS response.",
                "Add Strict-Transport-Security with an appropriate max-age, includeSubDomains where suitable, and preload only after validation.",
            )
        ]

    max_age = _hsts_max_age(header)
    if max_age is None:
        return [
            _finding(
                snapshot,
                "Medium",
                "Strict-Transport-Security max-age is missing",
                f"Strict-Transport-Security value was '{header}', but no max-age directive was found.",
                "Set max-age to a documented production value, commonly at least 15552000 seconds after rollout testing.",
            )
        ]
    if max_age < MIN_HSTS_MAX_AGE_SECONDS:
        return [
            _finding(
                snapshot,
                "Low",
                "Strict-Transport-Security max-age is short",
                f"Strict-Transport-Security max-age is {max_age}, below {MIN_HSTS_MAX_AGE_SECONDS} seconds.",
                "Increase max-age after confirming HTTPS readiness across the API domain and subdomains.",
            )
        ]
    return []


def _check_csp(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    header = headers.get("content-security-policy")
    if not header:
        return [
            _finding(
                snapshot,
                "Low",
                "Content-Security-Policy header is missing",
                "Content-Security-Policy was not present.",
                "Add a restrictive CSP where the API serves browser-readable or HTML error responses. At minimum, consider default-src 'none' for API responses.",
            )
        ]
    lowered = header.lower()
    weak_tokens = [token for token in ["'unsafe-inline'", "'unsafe-eval'", "default-src *", "script-src *"] if token in lowered]
    if weak_tokens:
        return [
            _finding(
                snapshot,
                "Medium",
                "Content-Security-Policy contains weak directives",
                f"Content-Security-Policy includes weak directive(s): {', '.join(weak_tokens)}.",
                "Remove wildcard script/default sources and unsafe directives. Prefer default-src 'none' for pure API responses.",
            )
        ]
    return []


def _check_x_content_type_options(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    header = headers.get("x-content-type-options")
    if not header:
        return [
            _finding(
                snapshot,
                "Medium",
                "X-Content-Type-Options header is missing",
                "X-Content-Type-Options was not present.",
                "Return X-Content-Type-Options: nosniff to reduce browser MIME-sniffing risk.",
            )
        ]
    if header.strip().lower() != "nosniff":
        return [
            _finding(
                snapshot,
                "Medium",
                "X-Content-Type-Options header is weak",
                f"X-Content-Type-Options value was '{header}', expected 'nosniff'.",
                "Set X-Content-Type-Options exactly to nosniff.",
            )
        ]
    return []


def _check_x_frame_options(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    header = headers.get("x-frame-options")
    if not header:
        return [
            _finding(
                snapshot,
                "Low",
                "X-Frame-Options header is missing",
                "X-Frame-Options was not present.",
                "Return X-Frame-Options: DENY or SAMEORIGIN for browser-rendered responses, or enforce equivalent frame-ancestors in CSP.",
            )
        ]
    if header.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return [
            _finding(
                snapshot,
                "Low",
                "X-Frame-Options header is weak",
                f"X-Frame-Options value was '{header}', expected DENY or SAMEORIGIN.",
                "Use DENY or SAMEORIGIN, or migrate to a strict CSP frame-ancestors directive.",
            )
        ]
    return []


def _check_referrer_policy(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    header = headers.get("referrer-policy")
    if not header:
        return [
            _finding(
                snapshot,
                "Low",
                "Referrer-Policy header is missing",
                "Referrer-Policy was not present.",
                "Set Referrer-Policy to no-referrer, same-origin, or strict-origin-when-cross-origin based on application needs.",
            )
        ]
    weak_values = {"unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"}
    if header.strip().lower() in weak_values:
        return [
            _finding(
                snapshot,
                "Medium",
                "Referrer-Policy header is weak",
                f"Referrer-Policy value was '{header}'.",
                "Use no-referrer, same-origin, or strict-origin-when-cross-origin to limit leakage of sensitive URLs.",
            )
        ]
    return []


def _check_permissions_policy(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    header = headers.get("permissions-policy")
    if not header:
        return [
            _finding(
                snapshot,
                "Low",
                "Permissions-Policy header is missing",
                "Permissions-Policy was not present.",
                "Set Permissions-Policy to disable unused browser capabilities such as camera, microphone, geolocation, and payment.",
            )
        ]
    if "*" in header:
        return [
            _finding(
                snapshot,
                "Medium",
                "Permissions-Policy allows wildcard access",
                f"Permissions-Policy value was '{header}'.",
                "Remove wildcard permissions and explicitly disable or narrowly allow required browser features.",
            )
        ]
    return []


def _check_sensitive_cache_control(snapshot: ResponseSnapshot, headers: dict[str, str]) -> list[FindingDraft]:
    if snapshot.status_code not in SUCCESS_STATUSES or not _is_sensitive_endpoint(snapshot.endpoint_path):
        return []

    header = headers.get("cache-control")
    if not header:
        return [
            _finding(
                snapshot,
                "High",
                "Cache-Control is missing on sensitive endpoint",
                "Sensitive-looking endpoint returned a successful response without Cache-Control.",
                "Return Cache-Control: no-store for sensitive user, admin, payment, billing, and profile responses.",
            )
        ]

    directives = _cache_directives(header)
    weak_reasons: list[str] = []
    if "public" in directives:
        weak_reasons.append("public caching is allowed")
    if "no-store" not in directives:
        weak_reasons.append("no-store is missing")
    if any(directive.startswith("max-age") or directive.startswith("s-maxage") for directive in directives):
        weak_reasons.append("explicit cache lifetime is present")

    if weak_reasons:
        return [
            _finding(
                snapshot,
                "High" if "public" in directives else "Medium",
                "Cache-Control is weak on sensitive endpoint",
                f"Cache-Control value was '{header}'; {', '.join(weak_reasons)}.",
                "Use Cache-Control: no-store for sensitive API responses and avoid public or long-lived caching directives.",
            )
        ]
    return []


def _finding(snapshot: ResponseSnapshot, severity: str, title: str, evidence: str, recommendation: str) -> FindingDraft:
    return FindingDraft(
        endpoint_path=snapshot.endpoint_path,
        check_name="security_headers",
        severity=severity,
        title=title,
        evidence=f"Affected endpoint: {snapshot.endpoint_path}. {evidence}",
        recommendation=recommendation,
        risk_score=RISK_BY_SEVERITY[severity],
    )


def _headers_lower(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def _hsts_max_age(value: str) -> int | None:
    match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", value, re.I)
    return int(match.group(1)) if match else None


def _cache_directives(value: str) -> set[str]:
    return {part.strip().lower() for part in value.split(",") if part.strip()}


def _is_sensitive_endpoint(path: str) -> bool:
    return any(pattern.search(path) for pattern in SENSITIVE_PATH_PATTERNS)
