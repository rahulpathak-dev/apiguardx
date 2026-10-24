from dataclasses import dataclass, field


@dataclass(frozen=True)
class ResponseSnapshot:
    url: str
    endpoint_path: str
    status_code: int
    headers: dict[str, str]
    body: str
    method: str = "GET"
    elapsed_ms: float = 0.0
    observed_statuses: tuple[int, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class FindingDraft:
    endpoint_path: str
    check_name: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    risk_score: int = 0
