from datetime import UTC, datetime

from fastapi import status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import AppError
from app.models import ApiProject, AuditAction, Finding, Scan, User
from app.scanner.service import run_scan
from app.schemas import AnalyticsRead, FindingUpdate, ScanCompareRead, ScanCreate, ScanFindingCompareRead
from app.services.audit import record_audit_event
from app.services.projects import get_owned_project


def list_user_scans(db: Session, user: User, target_id: int | None = None, severity: str | None = None) -> list[Scan]:
    stmt = (
        select(Scan)
        .join(ApiProject)
        .where(ApiProject.owner_id == user.id)
        .options(selectinload(Scan.findings))
        .order_by(Scan.created_at.desc())
    )
    if target_id is not None:
        stmt = stmt.where(Scan.project_id == target_id)
    if severity:
        stmt = stmt.where(Scan.findings.any(Finding.severity == severity))
    return list(db.scalars(stmt))


def create_user_scan(db: Session, user: User, payload: ScanCreate) -> Scan:
    project = get_owned_project(db, payload.target_id, user)
    if not project.authorization_ack:
        raise AppError("Target authorization has not been acknowledged", status.HTTP_400_BAD_REQUEST, "authorization_required")
    scan = run_scan(db=db, target=project, endpoint_ids=payload.endpoint_ids)
    record_audit_event(
        db,
        actor_user_id=user.id,
        project_id=project.id,
        action=AuditAction.run_scan.value,
        entity_type="scan",
        entity_id=scan.id,
        metadata={"risk_score": scan.total_risk_score, "endpoint_count": len(payload.endpoint_ids)},
    )
    db.commit()
    return scan


def get_user_scan(db: Session, user: User, scan_id: int, severity: str | None = None) -> Scan:
    scan = db.scalar(
        select(Scan)
        .join(ApiProject)
        .where(Scan.id == scan_id, ApiProject.owner_id == user.id)
        .options(selectinload(Scan.findings))
    )
    if scan is None:
        raise AppError("Scan not found", status.HTTP_404_NOT_FOUND, "scan_not_found")
    if severity:
        scan.findings = [finding for finding in scan.findings if finding.severity == severity]
    return scan


def update_user_finding(db: Session, user: User, finding_id: int, payload: FindingUpdate) -> Finding:
    finding = db.scalar(
        select(Finding)
        .join(Scan)
        .join(ApiProject)
        .where(Finding.id == finding_id, ApiProject.owner_id == user.id)
    )
    if finding is None:
        raise AppError("Finding not found", status.HTTP_404_NOT_FOUND, "finding_not_found")

    if payload.is_reviewed is not None:
        finding.is_reviewed = payload.is_reviewed
        finding.reviewed_at = datetime.now(UTC) if payload.is_reviewed else None
        finding.reviewed_by_user_id = user.id if payload.is_reviewed else None
    if payload.review_notes is not None:
        finding.review_notes = payload.review_notes.strip() or None

    db.commit()
    db.refresh(finding)
    return finding


def compare_latest_user_scans(db: Session, user: User, target_id: int) -> ScanCompareRead:
    get_owned_project(db, target_id, user)
    scans = list(
        db.scalars(
            select(Scan)
            .where(Scan.project_id == target_id, Scan.status == "completed")
            .options(selectinload(Scan.findings))
            .order_by(Scan.completed_at.desc().nullslast(), Scan.created_at.desc())
            .limit(2)
        )
    )
    latest = scans[0] if scans else None
    previous = scans[1] if len(scans) > 1 else None

    latest_map = _finding_map(latest.findings if latest else [])
    previous_map = _finding_map(previous.findings if previous else [])
    latest_keys = set(latest_map)
    previous_keys = set(previous_map)

    return ScanCompareRead(
        target_id=target_id,
        latest_scan_id=latest.id if latest else None,
        previous_scan_id=previous.id if previous else None,
        new_findings=[_compare_read(latest_map[key]) for key in sorted(latest_keys - previous_keys)],
        resolved_findings=[_compare_read(previous_map[key]) for key in sorted(previous_keys - latest_keys)],
        persistent_findings=[_compare_read(latest_map[key]) for key in sorted(latest_keys & previous_keys)],
    )


def get_user_analytics(db: Session, user: User) -> AnalyticsRead:
    scan_ids = select(Scan.id).join(ApiProject).where(ApiProject.owner_id == user.id)
    scan_count = db.scalar(select(func.count()).select_from(Scan).join(ApiProject).where(ApiProject.owner_id == user.id)) or 0
    finding_count = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id.in_(scan_ids))) or 0
    avg_score = db.scalar(select(func.avg(Scan.total_risk_score)).join(ApiProject).where(ApiProject.owner_id == user.id)) or 0
    severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    rows = db.execute(select(Finding.severity, func.count()).where(Finding.scan_id.in_(scan_ids)).group_by(Finding.severity)).all()
    for severity, count in rows:
        severity_counts[str(severity)] = int(count)
    return AnalyticsRead(
        scan_count=int(scan_count),
        finding_count=int(finding_count),
        average_risk_score=round(float(avg_score), 2),
        severity_counts=severity_counts,
    )


def _finding_map(findings: list[Finding]) -> dict[tuple[str, str, str], Finding]:
    return {(finding.endpoint_path, finding.check_name, finding.title): finding for finding in findings}


def _compare_read(finding: Finding) -> ScanFindingCompareRead:
    return ScanFindingCompareRead(
        endpoint_path=finding.endpoint_path,
        check_name=finding.check_name,
        severity=finding.severity,
        title=finding.title,
    )

