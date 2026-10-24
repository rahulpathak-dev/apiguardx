from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings, settings
from app.core.exceptions import AppError
from app.core.security import decode_token_payload
from app.core.url_security import normalize_target_url
from app.db.session import SessionLocal
from app.models import AuditLog
from app.main import app


def _auth_headers(client: TestClient) -> dict[str, str]:
    email = f"hardening-{uuid4().hex}@example.com"
    password = "StrongPassword123!"
    client.post("/auth/register", json={"email": email, "full_name": "Hardening Owner", "password": password})
    response = client.post("/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_project_url_ssrf_protection_blocks_local_targets() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        response = client.post(
            "/targets",
            headers=headers,
            json={"name": "Metadata API", "base_url": "http://169.254.169.254", "authorization_ack": True},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "target_host_blocked"


def test_endpoint_path_validation_rejects_absolute_urls() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        project = client.post(
            "/targets",
            headers=headers,
            json={"name": "Safe API", "base_url": f"https://safe-{uuid4().hex}.example.com", "authorization_ack": True},
        )
        response = client.post(
            "/endpoints",
            headers=headers,
            json={"target_id": project.json()["id"], "method": "GET", "path": "https://evil.example.com/admin"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_endpoint_path"


def test_validation_errors_do_not_echo_raw_inputs() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/auth/register",
            json={"email": "not-an-email", "full_name": "A", "password": "SensitiveButInvalid123!"},
        )
        assert response.status_code == 422
        body = response.json()
        assert "input" not in str(body)
        assert "SensitiveButInvalid123!" not in str(body)


def test_rate_limiting_returns_safe_429(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_rate_limit_authenticated_requests", 1)
    monkeypatch.setattr(settings, "api_rate_limit_window_seconds", 60)
    headers = {"Authorization": f"Bearer safe-429-{uuid4().hex}"}
    with TestClient(app) as client:
        assert client.get("/docs", headers=headers).status_code in {200, 404}
        response = client.get("/docs", headers=headers)
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "rate_limited"
        assert "Retry-After" in response.headers


def test_rate_limiting_is_not_bypassed_by_path_rotation(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_rate_limit_authenticated_requests", 2)
    monkeypatch.setattr(settings, "api_rate_limit_window_seconds", 60)
    headers = {"Authorization": f"Bearer path-rotation-{uuid4().hex}"}
    with TestClient(app) as client:
        assert client.get("/docs", headers=headers).status_code in {200, 404}
        assert client.get("/openapi.json", headers=headers).status_code in {200, 404}
        response = client.get(f"/missing-{uuid4().hex}", headers=headers)
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "rate_limited"


def test_rate_limiting_uses_distinct_token_buckets(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_rate_limit_authenticated_requests", 1)
    monkeypatch.setattr(settings, "api_rate_limit_window_seconds", 60)
    first = {"Authorization": f"Bearer token-one-{uuid4().hex}"}
    second = {"Authorization": f"Bearer token-two-{uuid4().hex}"}
    with TestClient(app) as client:
        assert client.get("/docs", headers=first).status_code in {200, 404}
        assert client.get("/docs", headers=second).status_code in {200, 404}
        response = client.get("/docs", headers=first)
        assert response.status_code == 429

def test_url_allowlist_and_blocklist_are_enforced(monkeypatch) -> None:
    monkeypatch.setattr(settings, "scanner_allowed_hosts", "*.example.com")
    monkeypatch.setattr(settings, "scanner_blocked_hosts", "blocked.example.com")

    assert normalize_target_url("https://api.example.com/v1") == "https://api.example.com/v1"

    with pytest.raises(AppError) as blocked:
        normalize_target_url("https://blocked.example.com")
    assert blocked.value.code == "target_host_blocked"

    with pytest.raises(AppError) as not_allowed:
        normalize_target_url("https://outside.test")
    assert not_allowed.value.code == "target_host_not_allowed"


def test_jwt_contains_expected_security_claims() -> None:
    with TestClient(app) as client:
        email = f"jwt-{uuid4().hex}@example.com"
        password = "StrongPassword123!"
        client.post("/auth/register", json={"email": email, "full_name": "JWT Owner", "password": password})
        response = client.post("/auth/login", json={"email": email, "password": password})
        payload = decode_token_payload(response.json()["access_token"])
        assert payload["iss"] == settings.jwt_issuer
        assert payload["aud"] == settings.jwt_audience
        assert payload["type"] == "access"
        assert payload["jti"]


def test_local_dev_uses_sqlite_when_compose_db_host_is_unreachable() -> None:
    local_settings = Settings(
        environment="development",
        database_url="postgresql+psycopg://apiguardx:change-me@db:5432/apiguardx",
    )
    if Path("/.dockerenv").exists():
        assert "@db:" in local_settings.database_url
    else:
        assert local_settings.database_url.startswith("sqlite:///")


def test_production_rejects_default_secrets() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="production", jwt_secret_key="replace-with-a-long-random-secret")

def test_request_id_header_is_sanitized() -> None:
    with TestClient(app) as client:
        response = client.get("/health", headers={settings.request_id_header: "bad id\r\nInjected: yes"})
        assert response.status_code == 200
        assert "\r" not in response.headers[settings.request_id_header]
        assert "\n" not in response.headers[settings.request_id_header]
        assert response.headers[settings.request_id_header].startswith("bad-id")


def test_production_requires_dns_ssrf_verification() -> None:
    with pytest.raises(ValidationError):
        Settings(
            environment="production",
            jwt_secret_key="a-production-secret-with-more-than-32-characters",
            database_url="postgresql+psycopg://apiguardx:strong-password@db:5432/apiguardx",
            trusted_hosts="api.example.com",
            backend_cors_origins="https://app.example.com",
            scanner_resolve_dns_for_ssrf=False,
            scanner_allow_private_networks=False,
        )


def test_audit_metadata_is_structured_json() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        created = client.post(
            "/targets",
            headers=headers,
            json={"name": "Audit API", "base_url": f"https://audit-{uuid4().hex}.example.com", "authorization_ack": True},
        )
        assert created.status_code == 201

    with SessionLocal() as db:
        log = db.query(AuditLog).filter(AuditLog.action == "create_project").order_by(AuditLog.id.desc()).first()
        assert isinstance(log.metadata_json, dict)
        assert "base_url_host" in log.metadata_json




