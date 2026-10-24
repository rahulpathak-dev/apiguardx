from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import TokenDecodeError, decode_token_payload
from app.db.session import get_db
from app.models import AuthTokenRevocation, User


bearer = HTTPBearer(auto_error=False)
AUTH_HEADERS = {"WWW-Authenticate": "Bearer"}


def get_current_token_payload(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token", headers=AUTH_HEADERS)
    try:
        payload = decode_token_payload(credentials.credentials)
    except TokenDecodeError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token", headers=AUTH_HEADERS) from None

    token_id = str(payload["jti"])
    revoked = db.scalar(select(AuthTokenRevocation).where(AuthTokenRevocation.token_id == token_id))
    if revoked is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked", headers=AUTH_HEADERS)
    return payload


def get_current_user(
    payload: dict[str, Any] = Depends(get_current_token_payload),
    db: Session = Depends(get_db),
) -> User:
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or missing user", headers=AUTH_HEADERS)
    return user
