from __future__ import annotations

import secrets
from datetime import UTC, datetime

from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.exceptions import AppError
from app.core.security import hash_password, verify_password
from app.models import ApiProject, AuditAction, AuditLog, CiCdToken, Endpoint, Scan, User
from app.scanner.service import run_scan
from app.schemas import CiCdScanRequest, CiCdScanResponse, CiCdTokenCreate
from app.services.projects import get_owned_project


TOKEN_PREFIX = "agx"


def create_ci_token(db: Session, user: User, payload: CiCdTokenCreate) -> tuple[CiCdToken, str]:
    project = get_owned_project(db, payload.project_id, user)
    if not project.authorization_ack:
        raise AppError("Target authorization has not been acknowledged", status.HTTP_400_BAD_REQUEST, "authorization_required")

    token_value = _generate_token_value()
    token_prefix = _token_lookup_prefix(token_value)
    token = CiCdToken(
        owner_id=user.id,
        project_id=project.id,
        name=payload.name,
        token_prefix=token_prefix,
        token_hash=hash_password(token_value),
        expires_at=payload.expires_at,
    )
    db.add(token)
    db.flush()
    _audit(db, user.id, project.id, AuditAction.create_ci_token.value, "ci_cd_token", token.id)
    db.commit()
    db.refresh(token)
    return token, token_value


def list_ci_tokens(db: Session, user: User, project_id: int | None = None) -> list[CiCdToken]:
    stmt = select(CiCdToken).where(CiCdToken.owner_id == user.id).order_by(CiCdToken.created_at.desc())
    if project_id is not None:
        get_owned_project(db, project_id, user)
        stmt = stmt.where(CiCdToken.project_id == project_id)
    return list(db.scalars(stmt))


def revoke_ci_token(db: Session, user: User, token_id: int) -> CiCdToken:
    token = db.scalar(select(CiCdToken).where(CiCdToken.id == token_id, CiCdToken.owner_id == user.id))
    if token is None:
        raise AppError("CI/CD token not found", status.HTTP_404_NOT_FOUND, "ci_token_not_found")
    if token.is_active:
        token.is_active = False
        token.revoked_at = datetime.now(UTC)
        _audit(db, user.id, token.project_id, AuditAction.revoke_ci_token.value, "ci_cd_token", token.id)
        db.commit()
        db.refresh(token)
    return token


def authenticate_ci_token(db: Session, raw_token: str | None) -> CiCdToken:
    if not raw_token:
        raise AppError("Missing CI/CD token", status.HTTP_401_UNAUTHORIZED, "ci_token_missing")
    token_prefix = _token_lookup_prefix(raw_token)
    candidates = list(
        db.scalars(
            select(CiCdToken)
            .where(CiCdToken.token_prefix == token_prefix, CiCdToken.is_active.is_(True))
            .options(selectinload(CiCdToken.project), selectinload(CiCdToken.owner))
        )
    )
    now = datetime.now(UTC)
    for token in candidates:
        if token.expires_at is not None and _as_aware(token.expires_at) <= now:
            continue
        if verify_password(raw_token, token.token_hash):
            token.last_used_at = now
            db.commit()
            db.refresh(token)
            return token
    raise AppError("Invalid or expired CI/CD token", status.HTTP_401_UNAUTHORIZED, "ci_token_invalid")


def run_ci_scan(db: Session, token: CiCdToken, payload: CiCdScanRequest) -> CiCdScanResponse:
    project = db.get(ApiProject, token.project_id)
    if project is None or not project.authorization_ack:
        raise AppError("Authorized API project not found", status.HTTP_404_NOT_FOUND, "project_not_found")
    if payload.endpoint_ids:
        requested_ids = set(payload.endpoint_ids)
        owned_ids = set(db.scalars(select(Endpoint.id).where(Endpoint.project_id == project.id, Endpoint.id.in_(requested_ids))))
        if owned_ids != requested_ids:
            raise AppError("One or more endpoints are not part of this API project", status.HTTP_400_BAD_REQUEST, "invalid_endpoint_scope")
    scan = run_scan(db=db, target=project, endpoint_ids=payload.endpoint_ids)
    scan = db.scalar(select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.findings))) or scan
    _audit(db, token.owner_id, project.id, AuditAction.run_scan.value, "scan", scan.id)
    db.commit()
    passed = scan.total_risk_score <= payload.threshold
    return CiCdScanResponse(
        scan_id=scan.id,
        project_id=project.id,
        project_name=project.name,
        status=scan.status,
        risk_score=scan.total_risk_score,
        risk_grade=scan.risk_grade,
        threshold=payload.threshold,
        passed=passed,
        should_fail_pipeline=not passed,
        summary=scan.summary,
        severity_counts={
            "Critical": scan.critical_count,
            "High": scan.high_count,
            "Medium": scan.medium_count,
            "Low": scan.low_count,
        },
        findings=scan.findings,
        completed_at=scan.completed_at,
    )


def extract_ci_token(authorization: str | None, header_token: str | None) -> str | None:
    if header_token:
        return header_token.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def _generate_token_value() -> str:
    return f"{TOKEN_PREFIX}_{secrets.token_hex(6)}_{secrets.token_urlsafe(32)}"


def _token_lookup_prefix(raw_token: str) -> str:
    parts = raw_token.split("_")
    if len(parts) >= 3 and parts[0] == TOKEN_PREFIX:
        return f"{parts[0]}_{parts[1]}"
    return raw_token[:16]


def _as_aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _audit(db: Session, user_id: int | None, project_id: int | None, action: str, entity_type: str, entity_id: int | None) -> None:
    db.add(AuditLog(actor_user_id=user_id, project_id=project_id, action=action, entity_type=entity_type, entity_id=entity_id))


