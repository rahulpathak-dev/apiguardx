import httpx

from app.models import ApiTarget, Endpoint
from app.scanner.http_client import SafeHttpClient, UnsafeMethodError
from app.scanner.plugins import DEFAULT_PLUGINS, ScannerPlugin
from app.scanner.types import FindingDraft, ResponseSnapshot


class EndpointScanner:
    def __init__(self, plugins: list[ScannerPlugin] | None = None) -> None:
        self.plugins = plugins or DEFAULT_PLUGINS

    def scan(self, client: SafeHttpClient, target: ApiTarget, endpoint: Endpoint) -> tuple[ResponseSnapshot | None, list[FindingDraft]]:
        try:
            snapshot = client.execute(target, endpoint)
        except UnsafeMethodError as exc:
            return None, [self._error_finding(endpoint, "unsafe_method", "Low", "Unsafe endpoint method blocked", str(exc))]
        except httpx.TimeoutException as exc:
            return None, [self._error_finding(endpoint, "timeout", "Low", "Endpoint request timed out", str(exc)[:500])]
        except httpx.HTTPError as exc:
            return None, [self._error_finding(endpoint, "availability", "Low", "Endpoint scan request failed", str(exc)[:500])]

        findings: list[FindingDraft] = []
        for plugin in self.plugins:
            findings.extend(plugin.analyze(snapshot))
        return snapshot, findings

    @staticmethod
    def _error_finding(endpoint: Endpoint, check_name: str, severity: str, title: str, evidence: str) -> FindingDraft:
        return FindingDraft(
            endpoint_path=endpoint.path,
            check_name=check_name,
            severity=severity,
            title=title,
            evidence=evidence,
            recommendation="Verify endpoint availability, method safety, and network access from the scanner environment.",
            risk_score=5,
        )
