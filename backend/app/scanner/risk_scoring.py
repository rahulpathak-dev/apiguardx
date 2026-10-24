from dataclasses import dataclass
from typing import Iterable, Protocol
import re


SEVERITY_WEIGHTS = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}
AUTH_EXPOSURE_CHECKS = {"missing_auth", "inconsistent_auth"}
SECRET_EXPOSURE_CHECKS = {"exposed_secret"}
HIGH_CRITICALITY_PATTERNS = [
    re.compile(r"(^|/)(admin|internal|manage|management|root)(/|$)", re.I),
    re.compile(r"(^|/)(payment|payments|billing|invoice|invoices|checkout|subscription)(/|$)", re.I),
]
MEDIUM_CRITICALITY_PATTERNS = [
    re.compile(r"(^|/)(user|users|account|accounts|profile|profiles|me)(/|$)", re.I),
    re.compile(r"(^|/)(customer|customers|tenant|tenants|member|members)(/|$)", re.I),
]


class FindingLike(Protocol):
    endpoint_path: str
    check_name: str
    severity: str
    risk_score: int


class EndpointLike(Protocol):
    path: str


@dataclass(frozen=True)
class RiskScoreResult:
    total_score: int
    grade: str
    explanation: str
    severity_score: int
    count_score: int
    criticality_score: int
    auth_exposure_score: int
    secret_exposure_score: int


def calculate_risk_score(findings: Iterable[FindingLike], endpoints: Iterable[EndpointLike] = ()) -> RiskScoreResult:
    finding_list = list(findings)
    endpoint_paths = {endpoint.path for endpoint in endpoints}
    endpoint_paths.update(finding.endpoint_path for finding in finding_list)

    severity_score = min(60, sum(_finding_weight(finding) for finding in finding_list))
    count_score = min(15, len(finding_list) * 2)
    criticality_score = _criticality_score(finding_list, endpoint_paths)
    auth_exposure_score = _auth_exposure_score(finding_list)
    secret_exposure_score = _secret_exposure_score(finding_list)

    total = min(100, severity_score + count_score + criticality_score + auth_exposure_score + secret_exposure_score)
    grade = grade_for_score(total)
    explanation = explain_score(
        total_score=total,
        grade=grade,
        finding_count=len(finding_list),
        severity_score=severity_score,
        count_score=count_score,
        criticality_score=criticality_score,
        auth_exposure_score=auth_exposure_score,
        secret_exposure_score=secret_exposure_score,
    )
    return RiskScoreResult(
        total_score=total,
        grade=grade,
        explanation=explanation,
        severity_score=severity_score,
        count_score=count_score,
        criticality_score=criticality_score,
        auth_exposure_score=auth_exposure_score,
        secret_exposure_score=secret_exposure_score,
    )


def grade_for_score(score: int | float) -> str:
    normalized = max(0, min(100, int(round(score))))
    if normalized <= 10:
        return "A"
    if normalized <= 30:
        return "B"
    if normalized <= 55:
        return "C"
    if normalized <= 75:
        return "D"
    return "F"


def explain_score(
    total_score: int,
    grade: str,
    finding_count: int,
    severity_score: int,
    count_score: int,
    criticality_score: int,
    auth_exposure_score: int,
    secret_exposure_score: int,
) -> str:
    drivers: list[str] = [f"severity impact {severity_score}", f"finding volume {count_score}"]
    if criticality_score:
        drivers.append(f"endpoint criticality {criticality_score}")
    if auth_exposure_score:
        drivers.append(f"authentication exposure {auth_exposure_score}")
    if secret_exposure_score:
        drivers.append(f"secret exposure {secret_exposure_score}")
    if finding_count == 0:
        return "Grade A: no findings were recorded, so the API currently has minimal observed scanner risk."
    return f"Grade {grade}: total risk {total_score}/100 from {finding_count} finding(s), driven by " + ", ".join(drivers) + "."


def _finding_weight(finding: FindingLike) -> int:
    explicit = int(getattr(finding, "risk_score", 0) or 0)
    if explicit > 0:
        return min(40, explicit)
    return SEVERITY_WEIGHTS.get(finding.severity, 0)


def _criticality_score(findings: list[FindingLike], endpoint_paths: set[str]) -> int:
    high_paths = {path for path in endpoint_paths if _endpoint_criticality(path) == "high"}
    medium_paths = {path for path in endpoint_paths if _endpoint_criticality(path) == "medium"}
    high_finding_bonus = 10 if any(finding.endpoint_path in high_paths for finding in findings) else 0
    medium_finding_bonus = 6 if any(finding.endpoint_path in medium_paths for finding in findings) else 0
    coverage_bonus = 4 if high_paths and findings else 2 if medium_paths and findings else 0
    return min(15, high_finding_bonus + medium_finding_bonus + coverage_bonus)


def _auth_exposure_score(findings: list[FindingLike]) -> int:
    if any(finding.check_name in AUTH_EXPOSURE_CHECKS and finding.severity in {"High", "Critical"} for finding in findings):
        return 15
    if any(finding.check_name in AUTH_EXPOSURE_CHECKS for finding in findings):
        return 8
    return 0


def _secret_exposure_score(findings: list[FindingLike]) -> int:
    if any(finding.check_name in SECRET_EXPOSURE_CHECKS and finding.severity == "Critical" for finding in findings):
        return 25
    if any(finding.check_name in SECRET_EXPOSURE_CHECKS for finding in findings):
        return 15
    return 0


def _endpoint_criticality(path: str) -> str | None:
    if any(pattern.search(path) for pattern in HIGH_CRITICALITY_PATTERNS):
        return "high"
    if any(pattern.search(path) for pattern in MEDIUM_CRITICALITY_PATTERNS):
        return "medium"
    return None
