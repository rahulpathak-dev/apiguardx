from datetime import UTC, datetime
from typing import Any

from fastapi import status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AppError
from app.core.security import create_access_token, hash_password, verify_password
from app.models import AuditAction, AuthTokenRevocation, User
from app.schemas import LoginRequest, TokenResponse, UserCreate
from app.services.audit import record_audit_event


def register_user(db: Session, payload: UserCreate) -> User:
    existing = db.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        raise AppError("Email already registered", status.HTTP_409_CONFLICT, "email_registered")
    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    record_audit_event(db, actor_user_id=user.id, action=AuditAction.register.value, entity_type="user", entity_id=user.id)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, payload: LoginRequest) -> TokenResponse:
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise AppError("Invalid credentials", status.HTTP_401_UNAUTHORIZED, "invalid_credentials")
    if not user.is_active:
        raise AppError("User account is inactive", status.HTTP_403_FORBIDDEN, "inactive_user")
    token, expires_at, _token_id = create_access_token(str(user.id))
    record_audit_event(db, actor_user_id=user.id, action=AuditAction.login.value, entity_type="user", entity_id=user.id)
    db.commit()
    return TokenResponse(
        access_token=token,
        expires_in=settings.jwt_expire_minutes * 60,
        expires_at=expires_at,
        user=user,
    )


def revoke_current_token(db: Session, user: User, payload: dict[str, Any]) -> None:
    token_id = str(payload["jti"])
    existing = db.scalar(select(AuthTokenRevocation).where(AuthTokenRevocation.token_id == token_id))
    if existing is not None:
        return
    expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=UTC)
    db.add(AuthTokenRevocation(token_id=token_id, user_id=user.id, expires_at=expires_at))
    record_audit_event(db, actor_user_id=user.id, action="logout", entity_type="user", entity_id=user.id)
    db.commit()
