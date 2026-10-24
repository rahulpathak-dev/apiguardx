from datetime import UTC, datetime

from app.models import ApiProject, Scan, ScanFinding, ScanStatus
from app.reports.pdf import build_scan_pdf


def _scan_with_project(findings: list[ScanFinding]) -> Scan:
    project = ApiProject(
        id=1,
        owner_id=1,
        name="Payments API",
        base_url="https://api.example.com",
        authorization_ack=True,
        risk_score=88,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    scan = Scan(
        id=42,
        project_id=1,
        status=ScanStatus.completed.value,
        total_risk_score=88,
        max_severity="Critical",
        critical_count=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        summary="Completed 2 safe endpoint checks with 2 findings. Grade F: total risk 88/100 from 2 findings.",
        started_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )
    scan.project = project
    scan.findings = findings
    return scan


def test_build_scan_pdf_contains_professional_report_bytes() -> None:
    findings = [
        ScanFinding(
            endpoint_path="/payments/config",
            check_name="exposed_secret",
            severity="Critical",
            risk_score=40,
            title="Database connection URL exposed in API response",
            evidence="Endpoint: /payments/config. Secret type: database URL. Masked evidence: postgresql://[MASKED]@db.internal/app.",
            recommendation="Remove database connection strings from responses and rotate embedded credentials.",
        ),
        ScanFinding(
            endpoint_path="/admin/users",
            check_name="missing_auth",
            severity="High",
            risk_score=25,
            title="Sensitive endpoint appears publicly accessible",
            evidence="Affected endpoint: /admin/users. Unauthenticated safe GET request returned HTTP 200.",
            recommendation="Require authentication and authorization for sensitive resources.",
        ),
    ]

    pdf = build_scan_pdf(_scan_with_project(findings))

    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 3000


def test_build_scan_pdf_supports_no_findings() -> None:
    scan = _scan_with_project([])
    scan.total_risk_score = 0
    scan.summary = "Completed 1 safe endpoint checks with 0 findings. Grade A: no findings were recorded."
    pdf = build_scan_pdf(scan)

    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 2500
