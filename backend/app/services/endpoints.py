from typing import Any
from urllib.parse import urlsplit

from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import AppError
from app.models import AuditAction, Endpoint, User
from app.schemas import EndpointCreate, EndpointImportOpenAPI, EndpointImportResult
from app.services.audit import record_audit_event
from app.services.projects import get_owned_project


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
OPENAPI_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _normalize_path(path: str) -> str:
    path = path.strip()
    if not path:
        raise AppError("Endpoint path cannot be empty", status.HTTP_400_BAD_REQUEST, "invalid_endpoint_path")
    if any(ord(character) < 32 for character in path):
        raise AppError("Endpoint path contains control characters", status.HTTP_400_BAD_REQUEST, "invalid_endpoint_path")
    lowered = path.lower()
    lowered_without_slashes = lowered.lstrip("/")
    if lowered.startswith(("http://", "https://", "//")) or lowered_without_slashes.startswith(("http://", "https://")) or "\\" in path:
        raise AppError("Endpoint path must be a relative API path", status.HTTP_400_BAD_REQUEST, "invalid_endpoint_path")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise AppError("Endpoint path must be a relative API path without fragments", status.HTTP_400_BAD_REQUEST, "invalid_endpoint_path")
    normalized = path if path.startswith("/") else f"/{path}"
    return normalized[:1024]


def _validate_safe_method(method: str) -> str:
    normalized = method.upper().strip()
    if normalized not in SAFE_METHODS:
        raise AppError("Only GET, HEAD, and OPTIONS endpoints can be stored for safe scanning", status.HTTP_400_BAD_REQUEST, "unsafe_method")
    return normalized


def _find_endpoint(db: Session, target_id: int, method: str, path: str) -> Endpoint | None:
    return db.scalar(select(Endpoint).where(Endpoint.target_id == target_id, Endpoint.method == method, Endpoint.path == path))


def list_project_endpoints(db: Session, target_id: int, user: User) -> list[Endpoint]:
    get_owned_project(db, target_id, user)
    return list(db.scalars(select(Endpoint).where(Endpoint.target_id == target_id).order_by(Endpoint.path, Endpoint.method)))


def create_project_endpoint(db: Session, user: User, payload: EndpointCreate) -> Endpoint:
    get_owned_project(db, payload.target_id, user)
    method = _validate_safe_method(payload.method)
    path = _normalize_path(payload.path)
    existing = _find_endpoint(db, payload.target_id, method, path)
    if existing is not None:
        raise AppError("Endpoint already exists for this project", status.HTTP_409_CONFLICT, "duplicate_endpoint")
    endpoint = Endpoint(
        target_id=payload.target_id,
        method=method,
        path=path,
        description=payload.description.strip() if payload.description else None,
    )
    db.add(endpoint)
    db.flush()
    record_audit_event(
        db,
        actor_user_id=user.id,
        project_id=payload.target_id,
        action=AuditAction.create_endpoint.value,
        entity_type="endpoint",
        entity_id=endpoint.id,
        metadata={"method": method, "path": path},
    )
    db.commit()
    db.refresh(endpoint)
    return endpoint


def _operation_description(path: str, method: str, operation: Any) -> str | None:
    if not isinstance(operation, dict):
        return None
    summary = operation.get("summary") or operation.get("operationId") or operation.get("description")
    if summary is None:
        return f"Imported {method.upper()} {path}"
    return str(summary).strip()[:255]


def import_openapi_endpoints(db: Session, user: User, payload: EndpointImportOpenAPI) -> EndpointImportResult:
    get_owned_project(db, payload.target_id, user)
    imported: list[Endpoint] = []
    skipped_count = 0
    paths = payload.spec.get("paths", {})

    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            skipped_count += 1
            continue
        try:
            path = _normalize_path(raw_path)
        except AppError:
            skipped_count += 1
            continue
        for raw_method, operation in path_item.items():
            method_key = str(raw_method).lower()
            if method_key not in OPENAPI_METHODS:
                continue
            method = method_key.upper()
            if method not in SAFE_METHODS:
                skipped_count += 1
                continue
            if _find_endpoint(db, payload.target_id, method, path) is not None:
                skipped_count += 1
                continue
            endpoint = Endpoint(
                target_id=payload.target_id,
                method=method,
                path=path,
                description=_operation_description(path, method, operation),
            )
            db.add(endpoint)
            imported.append(endpoint)

    if imported:
        db.flush()
        record_audit_event(
            db,
            actor_user_id=user.id,
            project_id=payload.target_id,
            action="import_endpoints",
            entity_type="endpoint",
            metadata={"imported_count": len(imported), "skipped_count": skipped_count},
        )
    db.commit()
    for endpoint in imported:
        db.refresh(endpoint)

    return EndpointImportResult(imported_count=len(imported), skipped_count=skipped_count, endpoints=imported)
