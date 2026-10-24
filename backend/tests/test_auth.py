from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.schemas import UserCreate


def test_password_strength_validation_requires_complex_password() -> None:
    with pytest.raises(ValidationError):
        UserCreate(email="analyst@example.com", full_name="Security Analyst", password="weakpassword")


def test_jwt_login_protected_route_and_logout_revocation() -> None:
    email = f"user-{uuid4().hex}@example.com"
    password = "StrongPassword123!"

    with TestClient(app) as client:
        register_response = client.post(
            "/auth/register",
            json={"email": email, "full_name": "Security Analyst", "password": password},
        )
        assert register_response.status_code == 201

        login_response = client.post("/auth/login", json={"email": email, "password": password})
        assert login_response.status_code == 200
        login_body = login_response.json()
        assert login_body["token_type"] == "bearer"
        assert login_body["expires_in"] > 0
        assert login_body["user"]["email"] == email

        headers = {"Authorization": f"Bearer {login_body['access_token']}"}
        protected_response = client.get("/auth/protected", headers=headers)
        assert protected_response.status_code == 200
        assert protected_response.json()["authenticated"] is True

        logout_response = client.post("/auth/logout", headers=headers)
        assert logout_response.status_code == 200

        revoked_response = client.get("/auth/protected", headers=headers)
        assert revoked_response.status_code == 401
        assert revoked_response.json()["error"]["message"] == "Token has been revoked"
