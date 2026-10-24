from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import ApiProject, Endpoint, ScanStatus, User
from app.scanner.endpoint_scanner import EndpointScanner
from app.scanner.http_client import SafeHttpClient, UnsafeMethodError
from app.scanner.manager import ScanManager
from app.scanner.types import FindingDraft, ResponseSnapshot


def _target() -> ApiProject:
    return ApiProject(id=1, owner_id=1, name="Demo API", base_url="https://api.example.com", authorization_ack=True)


def _endpoint(method: str = "GET", path: str = "/health") -> Endpoint:
    return Endpoint(project_id=1, method=method, path=path, is_active=True)


def test_safe_http_client_captures_response_metadata() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert request.headers["user-agent"] == "APIGuardX/1.0"
        assert request.headers["origin"] == "https://apiguardx.invalid"
        return httpx.Response(
            200,
            headers={"Access-Control-Allow-Origin": "*", "X-Test": "captured"},
            text='{"ok": true}',
            request=request,
        )

    with SafeHttpClient(transport=httpx.MockTransport(handler), rate_limit_probe_delay_seconds=0) as client:
        snapshot = client.execute(_target(), _endpoint())

    assert snapshot.url == "https://api.example.com/health"
    assert snapshot.method == "GET"
    assert snapshot.status_code == 200
    assert snapshot.headers["x-test"] == "captured"
    assert snapshot.body == '{"ok": true}'
    assert snapshot.observed_statuses == (200, 200, 200)
    assert len(calls) == 3


def test_safe_http_client_blocks_unsafe_methods() -> None:
    with SafeHttpClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, request=request)), rate_limit_probe_delay_seconds=0) as client:
        try:
            client.execute(_target(), _endpoint(method="POST"))
        except UnsafeMethodError as exc:
            assert "POST" in str(exc)
        else:
            raise AssertionError("Unsafe methods must be blocked before request execution")


def test_endpoint_scanner_runs_plugins_and_converts_timeouts() -> None:
    def ok_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"}, text="ok", request=request)

    with SafeHttpClient(transport=httpx.MockTransport(ok_handler), rate_limit_probe_delay_seconds=0) as client:
        snapshot, findings = EndpointScanner().scan(client, _target(), _endpoint(path="/admin/users"))

    assert snapshot is not None
    assert {finding.check_name for finding in findings} >= {"missing_auth", "cors_policy", "security_headers", "rate_limiting"}

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("request timed out", request=request)

    with SafeHttpClient(transport=httpx.MockTransport(timeout_handler), rate_limit_probe_delay_seconds=0) as client:
        snapshot, findings = EndpointScanner().scan(client, _target(), _endpoint(path="/admin/users"))

    assert snapshot is None
    assert findings[0].check_name == "timeout"
    assert findings[0].severity == "Low"


class _DummyClient:
    def __enter__(self) -> "_DummyClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None


class _FakeEndpointScanner:
    def scan(self, client: _DummyClient, target: ApiProject, endpoint: Endpoint) -> tuple[ResponseSnapshot, list[FindingDraft]]:
        return (
            ResponseSnapshot(
                url=f"{target.base_url}{endpoint.path}",
                endpoint_path=endpoint.path,
                status_code=200,
                headers={"content-type": "application/json"},
                body="{}",
                observed_statuses=(200,),
            ),
            [
                FindingDraft(
                    endpoint_path=endpoint.path,
                    check_name="missing_auth",
                    severity="Medium",
                    title="Endpoint appears accessible without authentication",
                    evidence="Unauthenticated safe request returned HTTP 200.",
                    recommendation="Verify whether the endpoint is intended to be public.",
                    risk_score=12,
                )
            ],
        )


def test_scan_manager_persists_results(monkeypatch) -> None:
    monkeypatch.setattr("app.scanner.manager.SafeHttpClient", lambda: _DummyClient())

    with TestClient(app):
        db = SessionLocal()
        try:
            suffix = uuid4().hex
            user = User(email=f"scanner-{suffix}@example.com", full_name="Scanner Owner", password_hash="hashed")
            db.add(user)
            db.commit()
            db.refresh(user)

            project = ApiProject(
                owner_id=user.id,
                name="Scanner Persistence API",
                base_url=f"https://scanner-{suffix}.example.com",
                authorization_ack=True,
            )
            db.add(project)
            db.commit()
            db.refresh(project)

            endpoint = Endpoint(project_id=project.id, method="GET", path="/health", is_active=True)
            db.add(endpoint)
            db.commit()
            db.refresh(endpoint)

            scan = ScanManager(endpoint_scanner=_FakeEndpointScanner()).run(db, project, [endpoint.id])

            assert scan.status == ScanStatus.completed.value
            assert scan.total_risk_score == 22
            assert scan.max_severity == "Medium"
            assert scan.risk_grade == "B"
            assert "authentication exposure" in scan.risk_explanation
            assert scan.medium_count == 1
            assert len(scan.findings) == 1
            assert scan.findings[0].check_name == "missing_auth"
            assert endpoint.last_status_code == 200
            assert endpoint.last_risk_score == 22
            assert project.risk_score == 22
            assert project.last_scan_at is not None
        finally:
            db.close()


