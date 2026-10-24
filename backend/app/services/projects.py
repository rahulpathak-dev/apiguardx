from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.core.url_security import normalize_target_url
from app.models import ApiProject, AuditAction, User
from app.schemas import TargetCreate, TargetUpdate
from app.services.audit import record_audit_event


def _normalize_base_url(value: object) -> str:
    return normalize_target_url(value)


def get_owned_project(db: Session, project_id: int, user: User) -> ApiProject:
    project = db.get(ApiProject, project_id)
    if project is None or project.owner_id != user.id:
        raise AppError("API project not found", status.HTTP_404_NOT_FOUND, "project_not_found")
    return project


def _ensure_unique_base_url(db: Session, user: User, base_url: str, project_id: int | None = None) -> None:
    stmt = select(ApiProject).where(ApiProject.owner_id == user.id, ApiProject.base_url == base_url)
    if project_id is not None:
        stmt = stmt.where(ApiProject.id != project_id)
    existing = db.scalar(stmt)
    if existing is not None:
        raise AppError("API base URL already exists in your workspace", status.HTTP_409_CONFLICT, "duplicate_project_url")


def list_projects(db: Session, user: User) -> list[ApiProject]:
    return list(db.scalars(select(ApiProject).where(ApiProject.owner_id == user.id).order_by(ApiProject.created_at.desc())))


def create_project(db: Session, user: User, payload: TargetCreate) -> ApiProject:
    if not payload.authorization_ack:
        raise AppError("Written authorization acknowledgment is required", status.HTTP_400_BAD_REQUEST, "authorization_required")
    base_url = _normalize_base_url(payload.base_url)
    _ensure_unique_base_url(db, user, base_url)
    project = ApiProject(
        owner_id=user.id,
        name=payload.name.strip(),
        base_url=base_url,
        authorization_ack=True,
    )
    db.add(project)
    db.flush()
    record_audit_event(
        db,
        actor_user_id=user.id,
        project_id=project.id,
        action=AuditAction.create_project.value,
        entity_type="api_project",
        entity_id=project.id,
        metadata={"base_url_host": project.base_url.split("//", 1)[-1].split("/", 1)[0]},
    )
    db.commit()
    db.refresh(project)
    return project


def update_project(db: Session, user: User, project_id: int, payload: TargetUpdate) -> ApiProject:
    project = get_owned_project(db, project_id, user)
    changed_fields: list[str] = []
    if payload.name is not None:
        project.name = payload.name.strip()
        changed_fields.append("name")
    if payload.base_url is not None:
        base_url = _normalize_base_url(payload.base_url)
        _ensure_unique_base_url(db, user, base_url, project_id=project.id)
        project.base_url = base_url
        changed_fields.append("base_url")
    if payload.authorization_ack is not None:
        if not payload.authorization_ack:
            raise AppError("Written authorization acknowledgment cannot be removed", status.HTTP_400_BAD_REQUEST, "authorization_required")
        project.authorization_ack = payload.authorization_ack
        changed_fields.append("authorization_ack")
    if changed_fields:
        record_audit_event(
            db,
            actor_user_id=user.id,
            project_id=project.id,
            action="update_project",
            entity_type="api_project",
            entity_id=project.id,
            metadata={"changed_fields": changed_fields},
        )
    db.commit()
    db.refresh(project)
    return project


def delete_project(db: Session, user: User, project_id: int) -> None:
    project = get_owned_project(db, project_id, user)
    record_audit_event(
        db,
        actor_user_id=user.id,
        project_id=project.id,
        action="delete_project",
        entity_type="api_project",
        entity_id=project.id,
    )
    db.delete(project)
    db.commit()
