from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings


pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12, deprecated="auto")


class TokenDecodeError(Exception):
    pass


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def create_access_token(subject: str) -> tuple[str, datetime, str]:
    issued_at = datetime.now(UTC)
    expires_at = issued_at + timedelta(minutes=settings.jwt_expire_minutes)
    token_id = str(uuid4())
    payload: dict[str, Any] = {
        "sub": subject,
        "jti": token_id,
        "type": "access",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_at, token_id


def decode_token_payload(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
    except JWTError as exc:
        raise TokenDecodeError("Invalid or expired token") from exc
    if payload.get("type") != "access" or not payload.get("sub") or not payload.get("jti"):
        raise TokenDecodeError("Invalid token payload")
    return payload


def decode_access_token(token: str) -> str | None:
    try:
        payload = decode_token_payload(token)
    except TokenDecodeError:
        return None
    return str(payload["sub"])
