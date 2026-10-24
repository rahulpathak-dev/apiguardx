from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_token_payload, get_current_user
from app.db.session import get_db
from app.models import User
from app.schemas import LoginRequest, LogoutResponse, ProtectedRouteRead, TokenResponse, UserCreate, UserRead
from app.services.auth import authenticate_user, register_user, revoke_current_token


router = APIRouter()


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    return register_user(db, payload)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    return authenticate_user(db, payload)


@router.post("/logout", response_model=LogoutResponse)
def logout(
    current_user: User = Depends(get_current_user),
    token_payload: dict[str, Any] = Depends(get_current_token_payload),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    revoke_current_token(db, current_user, token_payload)
    return LogoutResponse()


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.get("/protected", response_model=ProtectedRouteRead)
def protected(current_user: User = Depends(get_current_user)) -> ProtectedRouteRead:
    return ProtectedRouteRead(user=current_user)
