from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


def _auth_headers(client: TestClient) -> dict[str, str]:
    email = f"endpoint-{uuid4().hex}@example.com"
    password = "StrongPassword123!"
    client.post("/auth/register", json={"email": email, "full_name": "Endpoint Owner", "password": password})
    response = client.post("/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _project(client: TestClient, headers: dict[str, str]) -> int:
    response = client.post(
        "/targets",
        headers=headers,
        json={"name": "Discovery API", "base_url": f"https://discovery-{uuid4().hex}.example.com", "authorization_ack": True},
    )
    assert response.status_code == 201
    return int(response.json()["id"])


def test_manual_endpoint_entry_and_listing() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        project_id = _project(client, headers)
        created = client.post(
            "/endpoints",
            headers=headers,
            json={"target_id": project_id, "method": "GET", "path": "health", "description": "Health check"},
        )
        assert created.status_code == 201
        assert created.json()["path"] == "/health"

        listed = client.get(f"/endpoints?target_id={project_id}", headers=headers)
        assert listed.status_code == 200
        assert listed.json()[0]["method"] == "GET"


def test_unsafe_endpoint_methods_are_rejected() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        project_id = _project(client, headers)
        response = client.post(
            "/endpoints",
            headers=headers,
            json={"target_id": project_id, "method": "POST", "path": "/payments", "description": "Unsafe mutation"},
        )
        assert response.status_code == 422


def test_openapi_import_only_stores_safe_endpoints_and_skips_duplicates() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        project_id = _project(client, headers)
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/health": {"get": {"summary": "Health check"}, "post": {"summary": "Unsafe create"}},
                "/status": {"head": {"summary": "Status headers"}, "options": {"summary": "CORS preflight"}},
            },
        }
        imported = client.post("/endpoints/import-openapi", headers=headers, json={"target_id": project_id, "spec": spec})
        assert imported.status_code == 201
        body = imported.json()
        assert body["imported_count"] == 3
        assert body["skipped_count"] == 1
        assert {endpoint["method"] for endpoint in body["endpoints"]} == {"GET", "HEAD", "OPTIONS"}

        duplicate = client.post("/endpoints/import-openapi", headers=headers, json={"target_id": project_id, "spec": spec})
        assert duplicate.status_code == 201
        assert duplicate.json()["imported_count"] == 0
        assert duplicate.json()["skipped_count"] == 4


def test_endpoint_listing_requires_project_ownership() -> None:
    with TestClient(app) as client:
        owner_headers = _auth_headers(client)
        other_headers = _auth_headers(client)
        project_id = _project(client, owner_headers)
        response = client.get(f"/endpoints?target_id={project_id}", headers=other_headers)
        assert response.status_code == 404
