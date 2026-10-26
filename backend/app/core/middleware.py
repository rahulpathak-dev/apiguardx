import hashlib
import re
import time
from collections import defaultdict, deque
from uuid import uuid4

from fastapi import FastAPI, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse, Response

from app.core.config import settings


REQUEST_ID_PATTERN = re.compile(r"[^A-Za-z0-9_.-]")
MAX_RATE_LIMIT_BUCKETS = 10_000


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = _sanitize_request_id(request.headers.get(settings.request_id_header))
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers[settings.request_id_header] = request_id
        response.headers["X-Process-Time"] = f"{time.perf_counter() - started:.4f}"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # Frontend and API run on different origins/ports in local and Docker setups.
        response.headers.setdefault("Cross-Origin-Resource-Policy", "cross-origin")
        if _is_sensitive_path(request.url.path):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")
        if settings.environment == "production":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not settings.api_rate_limit_enabled or request.url.path == "/health":
            return await call_next(request)

        now = time.monotonic()
        window = settings.api_rate_limit_window_seconds
        key = _rate_limit_key(request)
        limit = settings.api_rate_limit_authenticated_requests if _has_auth(request) else settings.api_rate_limit_public_requests
        self._prune(now, window)
        bucket = self._requests[key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(1, int(window - (now - bucket[0]))) if bucket else window
            request_id = getattr(request.state, "request_id", str(uuid4()))
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": {"code": "rate_limited", "message": "Too many requests", "request_id": request_id}},
                headers={"Retry-After": str(retry_after)},
            )
        bucket.append(now)
        return await call_next(request)

    def _prune(self, now: float, window: int) -> None:
        stale_keys = []
        for key, bucket in self._requests.items():
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if not bucket:
                stale_keys.append(key)
        for key in stale_keys:
            self._requests.pop(key, None)
        if len(self._requests) <= MAX_RATE_LIMIT_BUCKETS:
            return
        overflow = len(self._requests) - MAX_RATE_LIMIT_BUCKETS
        for key in list(self._requests.keys())[:overflow]:
            self._requests.pop(key, None)


def register_middleware(app: FastAPI) -> None:
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

def _sanitize_request_id(value: str | None) -> str:
    if not value:
        return str(uuid4())
    sanitized = REQUEST_ID_PATTERN.sub("-", value.strip())[:128].strip(".-_")
    return sanitized or str(uuid4())


def _rate_limit_key(request: Request) -> str:
    client_host = request.client.host if request.client else "unknown"
    auth = request.headers.get("authorization", "")
    ci_token = request.headers.get("x-apiguardx-token", "")
    if auth.lower().startswith("bearer "):
        token_marker = f"auth:{_token_fingerprint(auth[7:])}"
    elif ci_token:
        token_marker = f"ci:{_token_fingerprint(ci_token)}"
    else:
        token_marker = "public"
    return f"{client_host}:{token_marker}"


def _has_auth(request: Request) -> bool:
    return bool(request.headers.get("authorization") or request.headers.get("x-apiguardx-token"))


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _is_sensitive_path(path: str) -> bool:
    return path.startswith(("/auth", "/ci", "/scans", "/reports"))

