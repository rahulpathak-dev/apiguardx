from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import AppError
from app.models import ApiProject, AuditAction, Scan, User
from app.reports.pdf import build_scan_pdf
from app.services.audit import record_audit_event


def build_user_scan_pdf(db: Session, user: User, scan_id: int) -> bytes:
    scan = db.scalar(
        select(Scan)
        .join(ApiProject)
        .where(Scan.id == scan_id, ApiProject.owner_id == user.id)
        .options(selectinload(Scan.findings), selectinload(Scan.project))
    )
    if scan is None:
        raise AppError("Scan not found", status.HTTP_404_NOT_FOUND, "scan_not_found")
    pdf = build_scan_pdf(scan)
    record_audit_event(
        db,
        actor_user_id=user.id,
        project_id=scan.project_id,
        action=AuditAction.generate_report.value,
        entity_type="scan_report",
        entity_id=scan.id,
        metadata={"report_type": "pdf", "risk_score": scan.total_risk_score},
    )
    db.commit()
    return pdf
