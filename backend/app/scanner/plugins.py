from typing import Protocol

from app.scanner.checks import (
    check_cors,
    check_exposed_secrets,
    check_missing_auth,
    check_rate_limit,
    check_security_headers,
    check_stack_traces,
    check_status_code,
)
from app.scanner.types import FindingDraft, ResponseSnapshot


class ScannerPlugin(Protocol):
    name: str

    def analyze(self, snapshot: ResponseSnapshot) -> list[FindingDraft]:
        ...


class FunctionPlugin:
    def __init__(self, name: str, func):
        self.name = name
        self._func = func

    def analyze(self, snapshot: ResponseSnapshot) -> list[FindingDraft]:
        return self._func(snapshot)


class RateLimitPlugin:
    name = "rate_limiting"

    def analyze(self, snapshot: ResponseSnapshot) -> list[FindingDraft]:
        return check_rate_limit(snapshot, snapshot.observed_statuses)


DEFAULT_PLUGINS: list[ScannerPlugin] = [
    FunctionPlugin("missing_auth", check_missing_auth),
    FunctionPlugin("cors_policy", check_cors),
    FunctionPlugin("security_headers", check_security_headers),
    FunctionPlugin("status_code", check_status_code),
    FunctionPlugin("stack_trace", check_stack_traces),
    FunctionPlugin("exposed_secret", check_exposed_secrets),
    RateLimitPlugin(),
]
