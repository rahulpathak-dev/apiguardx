import re

from app.scanner.types import FindingDraft, ResponseSnapshot


PUBLIC_SUCCESS_STATUSES = {200, 201}
AUTH_REQUIRED_STATUSES = {401, 403, 407}

HIGH_SENSITIVITY_PATTERNS = [
    re.compile(r"(^|/)(admin|superuser|root|internal|manage|management)(/|$)", re.I),
    re.compile(r"(^|/)(payment|payments|billing|invoice|invoices|checkout|subscription)(/|$)", re.I),
]

MEDIUM_SENSITIVITY_PATTERNS = [
    re.compile(r"(^|/)(user|users|account|accounts|profile|profiles|me)(/|$)", re.I),
    re.compile(r"(^|/)(customer|customers|member|members|tenant|tenants)(/|$)", re.I),
]

RISK_BY_SEVERITY = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}


def check_missing_auth(snapshot: ResponseSnapshot) -> list[FindingDraft]:
    """Passively flag sensitive-looking endpoints that answer unauthenticated safe requests."""
    sensitivity = _path_sensitivity(snapshot.endpoint_path)
    if sensitivity is None:
        return []

    findings: list[FindingDraft] = []
    observed_statuses = snapshot.observed_statuses or (snapshot.status_code,)

    if snapshot.status_code in PUBLIC_SUCCESS_STATUSES:
        severity = "Critical" if sensitivity == "high" else "High"
        findings.append(
            FindingDraft(
                endpoint_path=snapshot.endpoint_path,
                check_name="missing_auth",
                severity=severity,
                title="Sensitive endpoint appears publicly accessible",
                evidence=(
                    f"Unauthenticated safe {snapshot.method} request to sensitive-looking path "
                    f"'{snapshot.endpoint_path}' returned HTTP {snapshot.status_code}."
                ),
                recommendation=(
                    "Verify that this endpoint is intended to be public. Require authentication and authorization "
                    "for sensitive admin, user, payment, billing, or profile resources."
                ),
                risk_score=RISK_BY_SEVERITY[severity],
            )
        )

    if _has_inconsistent_auth_behavior(observed_statuses):
        severity = "Medium"
        findings.append(
            FindingDraft(
                endpoint_path=snapshot.endpoint_path,
                check_name="inconsistent_auth",
                severity=severity,
                title="Inconsistent authentication behavior observed",
                evidence=(
                    "Safe unauthenticated checks observed both successful and auth-required responses: "
                    f"{', '.join(str(status) for status in sorted(set(observed_statuses)))}."
                ),
                recommendation=(
                    "Review route, gateway, cache, and authorization policy consistency so sensitive endpoints "
                    "return stable authentication-required responses when no valid credentials are supplied."
                ),
                risk_score=RISK_BY_SEVERITY[severity],
            )
        )

    return findings


def _path_sensitivity(path: str) -> str | None:
    if any(pattern.search(path) for pattern in HIGH_SENSITIVITY_PATTERNS):
        return "high"
    if any(pattern.search(path) for pattern in MEDIUM_SENSITIVITY_PATTERNS):
        return "medium"
    return None


def _has_inconsistent_auth_behavior(statuses: tuple[int, ...] | list[int]) -> bool:
    observed = set(statuses)
    return bool(observed & PUBLIC_SUCCESS_STATUSES and observed & AUTH_REQUIRED_STATUSES)
