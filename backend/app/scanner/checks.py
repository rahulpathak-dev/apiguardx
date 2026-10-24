from app.scanner.cors import check_cors
from app.scanner.error_traces import check_error_traces
from app.scanner.missing_auth import check_missing_auth
from app.scanner.rate_limits import check_rate_limit
from app.scanner.secrets import check_exposed_secrets
from app.scanner.security_headers import check_security_headers
from app.scanner.types import FindingDraft, ResponseSnapshot


SEVERITY_WEIGHT = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}
check_stack_traces = check_error_traces


def _risk(severity: str) -> int:
    return SEVERITY_WEIGHT.get(severity, 0)


def check_status_code(snapshot: ResponseSnapshot) -> list[FindingDraft]:
    if 500 <= snapshot.status_code <= 599:
        return [
            FindingDraft(
                endpoint_path=snapshot.endpoint_path,
                check_name="status_code",
                severity="Medium",
                title="Server error response observed",
                evidence=f"Safe {snapshot.method} request returned HTTP {snapshot.status_code}.",
                recommendation="Investigate server-side errors and return sanitized, stable API error responses.",
                risk_score=_risk("Medium"),
            )
        ]
    if snapshot.status_code == 404:
        return [
            FindingDraft(
                endpoint_path=snapshot.endpoint_path,
                check_name="status_code",
                severity="Low",
                title="Endpoint returned not found",
                evidence="Safe request returned HTTP 404.",
                recommendation="Verify that the endpoint path is current or remove it from scan scope.",
                risk_score=_risk("Low"),
            )
        ]
    return []


def score_findings(findings: list[FindingDraft]) -> int:
    return min(100, sum(finding.risk_score or SEVERITY_WEIGHT.get(finding.severity, 0) for finding in findings))
