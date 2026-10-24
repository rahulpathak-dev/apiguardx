from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


def _auth_headers(client: TestClient) -> dict[str, str]:
    email = f"project-{uuid4().hex}@example.com"
    password = "StrongPassword123!"
    client.post("/auth/register", json={"email": email, "full_name": "Project Owner", "password": password})
    response = client.post("/auth/login", json={"email": email, "password": password})
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_project_crud_flow() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        create_response = client.post(
            "/targets",
            headers=headers,
            json={"name": "Billing API", "base_url": "https://billing.example.com", "authorization_ack": True},
        )
        assert create_response.status_code == 201
        project_id = create_response.json()["id"]

        assert client.get("/targets", headers=headers).status_code == 200
        assert client.get(f"/targets/{project_id}", headers=headers).status_code == 200

        update_response = client.patch(
            f"/targets/{project_id}",
            headers=headers,
            json={"name": "Billing Core API", "base_url": "https://billing-core.example.com", "authorization_ack": True},
        )
        assert update_response.status_code == 200
        assert update_response.json()["name"] == "Billing Core API"
        assert update_response.json()["base_url"] == "https://billing-core.example.com"

        delete_response = client.delete(f"/targets/{project_id}", headers=headers)
        assert delete_response.status_code == 204
        assert client.get(f"/targets/{project_id}", headers=headers).status_code == 404


def test_duplicate_project_url_is_rejected() -> None:
    with TestClient(app) as client:
        headers = _auth_headers(client)
        payload = {"name": "Public API", "base_url": "https://duplicate.example.com", "authorization_ack": True}
        assert client.post("/targets", headers=headers, json=payload).status_code == 201
        duplicate = client.post("/targets", headers=headers, json={**payload, "name": "Duplicate API"})
        assert duplicate.status_code == 409


def test_project_ownership_is_enforced() -> None:
    with TestClient(app) as client:
        owner_headers = _auth_headers(client)
        other_headers = _auth_headers(client)
        created = client.post(
            "/targets",
            headers=owner_headers,
            json={"name": "Private API", "base_url": "https://private.example.com", "authorization_ack": True},
        )
        project_id = created.json()["id"]
        assert client.get(f"/targets/{project_id}", headers=other_headers).status_code == 404
        assert client.patch(f"/targets/{project_id}", headers=other_headers, json={"name": "Stolen"}).status_code == 404
        assert client.delete(f"/targets/{project_id}", headers=other_headers).status_code == 404
