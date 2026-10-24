from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models import ApiProject, Scan, ScanFinding


def _auth_headers(client: TestClient) -> dict[str, str]:
    email = f"ci-{uuid4().hex}@example.com"
    password = "StrongPassword123!"
    client.post("/auth/register", json={"email": email, "full_name": "CI Owner", "password": password})
    response = client.post("/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _create_project(client: TestClient, headers: dict[str, str]) -> int:
    response = client.post(
        "/targets",
        headers=headers,
        json={"name": "Pipeline API", "base_url": f"https://ci-{uuid4().hex}.example.com", "authorization_ack": True},
    )
    assert response.status_code == 201
    return int(response.json()["id"])


def _fake_run_scan(score: int):
    def run(db: Session, target: ApiProject, endpoint_ids: list[int] | None = None) -> Scan:
        now = datetime.now(UTC)
        scan = Scan(
            project_id=target.id,
            status="completed",
            total_risk_score=score,
            max_severity="Critical",
            critical_count=1,
            summary=f"Completed CI scan. Grade {Scan(project_id=target.id, total_risk_score=score).risk_grade}: simulated risk.",
            started_at=now,
            completed_at=now,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        db.add(
            ScanFinding(
                scan_id=scan.id,
                endpoint_path="/admin",
                check_name="missing_auth",
                severity="Critical",
                risk_score=40,
                title="Sensitive endpoint may be public",
                evidence="GET /admin returned 200 without authentication in a safe check.",
                recommendation="Require authentication and authorization for sensitive endpoints.",
            )
        )
        target.risk_score = score
        target.last_scan_at = now
        db.commit()
        db.refresh(scan)
        return scan

    return run


def test_ci_token_lifecycle_and_threshold_failure(monkeypatch) -> None:
    monkeypatch.setattr("app.services.ci_cd.run_scan", _fake_run_scan(81))

    with TestClient(app) as client:
        headers = _auth_headers(client)
        project_id = _create_project(client, headers)

        created = client.post("/ci/tokens", headers=headers, json={"project_id": project_id, "name": "GitHub Actions"})
        assert created.status_code == 201
        token_body = created.json()
        raw_token = token_body["token"]
        token_id = token_body["id"]
        assert raw_token.startswith("agx_")
        assert token_body["token_prefix"] in raw_token

        listed = client.get(f"/ci/tokens?project_id={project_id}", headers=headers)
        assert listed.status_code == 200
        assert listed.json()[0]["id"] == token_id
        assert "token" not in listed.json()[0]

        failed_scan = client.post("/ci/scan", headers={"X-APIGUARDX-TOKEN": raw_token}, json={"threshold": 70})
        assert failed_scan.status_code == 422
        failed_body = failed_scan.json()
        assert failed_body["risk_score"] == 81
        assert failed_body["passed"] is False
        assert failed_body["should_fail_pipeline"] is True
        assert failed_body["severity_counts"]["Critical"] == 1
        assert failed_body["findings"][0]["severity"] == "Critical"

        passed_scan = client.post("/ci/scan", headers={"Authorization": f"Bearer {raw_token}"}, json={"threshold": 90})
        assert passed_scan.status_code == 200
        assert passed_scan.json()["passed"] is True

        revoked = client.post(f"/ci/tokens/{token_id}/revoke", headers=headers)
        assert revoked.status_code == 200
        assert revoked.json()["is_active"] is False

        rejected = client.post("/ci/scan", headers={"X-APIGUARDX-TOKEN": raw_token}, json={"threshold": 90})
        assert rejected.status_code == 401


def test_ci_scan_rejects_missing_or_invalid_tokens() -> None:
    with TestClient(app) as client:
        missing = client.post("/ci/scan", json={"threshold": 70})
        assert missing.status_code == 401

        invalid = client.post("/ci/scan", headers={"X-APIGUARDX-TOKEN": "agx_invalid_invalid"}, json={"threshold": 70})
        assert invalid.status_code == 401
