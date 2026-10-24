from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.db.session import SessionLocal
from app.main import app
from app.models import ApiProject, Scan, ScanFinding, User


def _auth_headers(client: TestClient) -> tuple[dict[str, str], str]:
    email = f"history-{uuid4().hex}@example.com"
    password = "StrongPassword123!"
    client.post("/auth/register", json={"email": email, "full_name": "History Owner", "password": password})
    response = client.post("/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}, email


def _seed_history(email: str) -> tuple[int, int, int, int]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        project = ApiProject(
            owner_id=user.id,
            name="History API",
            base_url=f"https://history-{uuid4().hex}.example.com",
            authorization_ack=True,
        )
        db.add(project)
        db.commit()
        db.refresh(project)

        previous = Scan(
            project_id=project.id,
            status="completed",
            total_risk_score=30,
            max_severity="High",
            high_count=1,
            summary="Grade B: previous scan.",
            created_at=datetime.now(UTC) - timedelta(days=1),
            completed_at=datetime.now(UTC) - timedelta(days=1),
        )
        latest = Scan(
            project_id=project.id,
            status="completed",
            total_risk_score=80,
            max_severity="Critical",
            critical_count=1,
            high_count=1,
            summary="Grade F: latest scan.",
            created_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        db.add_all([previous, latest])
        db.commit()
        db.refresh(previous)
        db.refresh(latest)

        resolved = ScanFinding(
            scan_id=previous.id,
            endpoint_path="/old",
            check_name="security_headers",
            severity="High",
            risk_score=25,
            title="Old high finding",
            evidence="Old evidence",
            recommendation="Old remediation",
        )
        persistent_previous = ScanFinding(
            scan_id=previous.id,
            endpoint_path="/admin/users",
            check_name="missing_auth",
            severity="High",
            risk_score=25,
            title="Persistent auth finding",
            evidence="Previous evidence",
            recommendation="Require auth",
        )
        persistent_latest = ScanFinding(
            scan_id=latest.id,
            endpoint_path="/admin/users",
            check_name="missing_auth",
            severity="High",
            risk_score=25,
            title="Persistent auth finding",
            evidence="Latest evidence",
            recommendation="Require auth",
        )
        new = ScanFinding(
            scan_id=latest.id,
            endpoint_path="/secrets",
            check_name="exposed_secret",
            severity="Critical",
            risk_score=40,
            title="New secret finding",
            evidence="Masked secret evidence",
            recommendation="Rotate secret",
        )
        db.add_all([resolved, persistent_previous, persistent_latest, new])
        db.commit()
        db.refresh(new)
        return project.id, previous.id, latest.id, new.id
    finally:
        db.close()


def test_scan_history_filters_details_compare_and_finding_review() -> None:
    with TestClient(app) as client:
        headers, email = _auth_headers(client)
        project_id, previous_id, latest_id, finding_id = _seed_history(email)

        all_scans = client.get("/scans", headers=headers)
        assert all_scans.status_code == 200
        assert {scan["id"] for scan in all_scans.json()} >= {previous_id, latest_id}

        filtered = client.get(f"/scans?target_id={project_id}&severity=Critical", headers=headers)
        assert filtered.status_code == 200
        assert [scan["id"] for scan in filtered.json()] == [latest_id]

        detail = client.get(f"/scans/{latest_id}?severity=Critical", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["id"] == latest_id
        assert len(detail.json()["findings"]) == 1
        assert detail.json()["findings"][0]["severity"] == "Critical"

        comparison = client.get(f"/scans/compare/latest?target_id={project_id}", headers=headers)
        assert comparison.status_code == 200
        body = comparison.json()
        assert body["latest_scan_id"] == latest_id
        assert body["previous_scan_id"] == previous_id
        assert {finding["title"] for finding in body["new_findings"]} == {"New secret finding"}
        assert {finding["title"] for finding in body["resolved_findings"]} == {"Old high finding"}
        assert {finding["title"] for finding in body["persistent_findings"]} == {"Persistent auth finding"}

        reviewed = client.patch(
            f"/scans/findings/{finding_id}",
            headers=headers,
            json={"is_reviewed": True, "review_notes": "Accepted for sprint remediation."},
        )
        assert reviewed.status_code == 200
        assert reviewed.json()["is_reviewed"] is True
        assert reviewed.json()["review_notes"] == "Accepted for sprint remediation."
        assert reviewed.json()["reviewed_at"] is not None
