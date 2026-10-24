from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.main import app
from app.models import AuditLog, ApiProject, Scan, ScanFinding


def _fake_run_scan(db: Session, target: ApiProject, endpoint_ids: list[int] | None = None) -> Scan:
    now = datetime.now(UTC)
    scan = Scan(
        project_id=target.id,
        status="completed",
        total_risk_score=64,
        max_severity="High",
        high_count=1,
        medium_count=1,
        summary="Completed integration scan. Grade D: simulated API risk.",
        started_at=now,
        completed_at=now,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    findings = [
        ScanFinding(
            scan_id=scan.id,
            endpoint_path="/admin/users",
            check_name="missing_auth",
            severity="High",
            risk_score=25,
            title="Sensitive endpoint appears publicly accessible",
            evidence="Safe unauthenticated GET request returned HTTP 200.",
            recommendation="Require authentication and authorization.",
        ),
        ScanFinding(
            scan_id=scan.id,
            endpoint_path="/health",
            check_name="security_headers",
            severity="Medium",
            risk_score=12,
            title="Security headers are incomplete",
            evidence="Missing Content-Security-Policy.",
            recommendation="Set expected security headers at the API gateway.",
        ),
    ]
    db.add_all(findings)
    target.risk_score = scan.total_risk_score
    target.last_scan_at = now
    db.commit()
    db.refresh(scan)
    return scan


def test_authorized_user_can_complete_core_api_flow(monkeypatch) -> None:
    monkeypatch.setattr("app.services.scans.run_scan", _fake_run_scan)

    with TestClient(app) as client:
        email = f"flow-{uuid4().hex}@example.com"
        password = "StrongPassword123!"
        registered = client.post("/auth/register", json={"email": email, "full_name": "Flow Owner", "password": password})
        assert registered.status_code == 201

        logged_in = client.post("/auth/login", json={"email": email, "password": password})
        assert logged_in.status_code == 200
        headers = {"Authorization": f"Bearer {logged_in.json()['access_token']}"}

        project = client.post(
            "/targets",
            headers=headers,
            json={"name": "Integration API", "base_url": f"https://flow-{uuid4().hex}.example.com", "authorization_ack": True},
        )
        assert project.status_code == 201
        project_id = project.json()["id"]

        endpoint = client.post("/endpoints", headers=headers, json={"target_id": project_id, "method": "GET", "path": "/health"})
        assert endpoint.status_code == 201

        imported = client.post(
            "/endpoints/import-openapi",
            headers=headers,
            json={
                "target_id": project_id,
                "spec": {
                    "openapi": "3.0.0",
                    "paths": {
                        "/admin/users": {"get": {"summary": "List users"}},
                        "/payments": {"post": {"summary": "Unsafe method skipped"}},
                    },
                },
            },
        )
        assert imported.status_code == 201
        assert imported.json()["imported_count"] == 1
        assert imported.json()["skipped_count"] == 1

        scan = client.post("/scans", headers=headers, json={"target_id": project_id})
        assert scan.status_code == 201
        scan_body = scan.json()
        assert scan_body["total_risk_score"] == 64
        assert len(scan_body["findings"]) == 2

        analytics = client.get("/scans/analytics", headers=headers)
        assert analytics.status_code == 200
        assert analytics.json()["scan_count"] >= 1

        pdf = client.get(f"/reports/{scan_body['id']}.pdf", headers=headers)
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF")

        with SessionLocal() as db:
            actions = set(db.scalars(select(AuditLog.action)))
            assert {"register", "login", "create_project", "create_endpoint", "import_endpoints", "run_scan", "generate_report"} <= actions

