from app.scanner.risk_scoring import calculate_risk_score, grade_for_score
from app.scanner.types import FindingDraft


class EndpointStub:
    def __init__(self, path: str) -> None:
        self.path = path


def finding(endpoint_path: str, check_name: str, severity: str, risk_score: int) -> FindingDraft:
    return FindingDraft(
        endpoint_path=endpoint_path,
        check_name=check_name,
        severity=severity,
        title="Finding",
        evidence="Evidence",
        recommendation="Recommendation",
        risk_score=risk_score,
    )


def test_grade_boundaries() -> None:
    assert grade_for_score(0) == "A"
    assert grade_for_score(25) == "B"
    assert grade_for_score(50) == "C"
    assert grade_for_score(70) == "D"
    assert grade_for_score(90) == "F"


def test_risk_score_includes_auth_secret_count_and_criticality() -> None:
    findings = [
        finding("/admin/users", "missing_auth", "Critical", 40),
        finding("/payments/config", "exposed_secret", "Critical", 40),
        finding("/health", "security_headers", "Low", 5),
    ]

    result = calculate_risk_score(findings, [EndpointStub("/admin/users"), EndpointStub("/payments/config")])

    assert result.total_score == 100
    assert result.grade == "F"
    assert result.severity_score == 60
    assert result.count_score == 6
    assert result.criticality_score == 14
    assert result.auth_exposure_score == 15
    assert result.secret_exposure_score == 25
    assert "authentication exposure" in result.explanation
    assert "secret exposure" in result.explanation


def test_empty_scan_scores_as_grade_a() -> None:
    result = calculate_risk_score([], [])

    assert result.total_score == 0
    assert result.grade == "A"
    assert "no findings" in result.explanation
