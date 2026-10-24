from app.scanner.types import FindingDraft, ResponseSnapshot


RATE_LIMIT_HEADERS = {
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
}
SUCCESS_STATUSES = {200, 201, 202, 204, 206, 304}
RISK_BY_SEVERITY = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}


def check_rate_limit(snapshot: ResponseSnapshot, observed_statuses: list[int] | tuple[int, ...]) -> list[FindingDraft]:
    statuses = tuple(observed_statuses or (snapshot.status_code,))
    headers = _headers_lower(snapshot.headers)
    has_rate_headers = any(header in headers for header in RATE_LIMIT_HEADERS)
    saw_429 = 429 in statuses
    repeated = len(statuses) > 1
    successful_probe = repeated and all(status in SUCCESS_STATUSES for status in statuses)

    if saw_429:
        return []

    if successful_probe and not has_rate_headers:
        severity = "Medium"
        return [
            _finding(
                snapshot=snapshot,
                severity=severity,
                title="Suspicious unlimited access during limited safe probe",
                evidence=(
                    f"Observed statuses across {len(statuses)} delayed safe request(s): {_format_statuses(statuses)}. "
                    "No HTTP 429 response or standard rate-limit headers were observed."
                ),
                recommendation=(
                    "Apply rate limiting at the API gateway or application layer, return standard rate-limit headers, "
                    "and ensure excessive unauthenticated or authenticated traffic receives HTTP 429."
                ),
            )
        ]

    if not has_rate_headers:
        severity = "Low"
        return [
            _finding(
                snapshot=snapshot,
                severity=severity,
                title="Rate-limit headers are missing",
                evidence=(
                    f"Observed statuses across {len(statuses)} safe request(s): {_format_statuses(statuses)}. "
                    "No standard rate-limit headers were present."
                ),
                recommendation="Return standard RateLimit-* or X-RateLimit-* headers so clients can understand enforced limits.",
            )
        ]

    if repeated and not saw_429:
        severity = "Low"
        return [
            _finding(
                snapshot=snapshot,
                severity=severity,
                title="No rate-limit response observed during limited safe probe",
                evidence=(
                    f"Observed statuses across {len(statuses)} delayed safe request(s): {_format_statuses(statuses)}. "
                    "Rate-limit headers were present, but no HTTP 429 response occurred during the conservative probe."
                ),
                recommendation="Verify configured thresholds are appropriate for the endpoint risk and abuse profile.",
            )
        ]

    return []


def _finding(snapshot: ResponseSnapshot, severity: str, title: str, evidence: str, recommendation: str) -> FindingDraft:
    return FindingDraft(
        endpoint_path=snapshot.endpoint_path,
        check_name="rate_limiting",
        severity=severity,
        title=title,
        evidence=f"Endpoint: {snapshot.endpoint_path}. {evidence}",
        recommendation=recommendation,
        risk_score=RISK_BY_SEVERITY[severity],
    )


def _headers_lower(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def _format_statuses(statuses: tuple[int, ...]) -> str:
    return ", ".join(str(status) for status in statuses)
