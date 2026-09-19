import pytest
import jwt
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def get_test_developer_token(email="dev_user@example.com", name="Test Developer"):
    payload = {
        "email": email,
        "name": name,
        "sub": f"sub_{email}",
        "email_verified": True,
        "iss": "https://accounts.google.com",
    }
    mock_jwt = jwt.encode(payload, key="test-mock-secret-key-must-be-32-bytes-long!", algorithm="HS256")
    res = client.post("/api/v1/auth/google", json={"credential": mock_jwt})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_unauthenticated_developer_endpoints():
    res = client.get("/api/v1/developer/keys")
    assert res.status_code == 401

    res = client.post("/api/v1/developer/keys", json={"name": "My App Key"})
    assert res.status_code == 401


def test_developer_key_lifecycle():
    token = get_test_developer_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create a developer key
    create_res = client.post(
        "/api/v1/developer/keys",
        json={"name": "Mobile SDK Key"},
        headers=headers,
    )
    assert create_res.status_code == 201
    key_data = create_res.json()

    assert key_data["name"] == "Mobile SDK Key"
    assert "secret_key" in key_data
    assert key_data["secret_key"].startswith("lon_live_")
    assert key_data["tier"] == "free"
    assert key_data["monthly_limit"] == 1000  # Default Free Developer tier
    assert key_data["is_active"] is True

    key_id = key_data["id"]
    secret_key = key_data["secret_key"]

    # 2. List developer keys — secret_key must NOT be present in list response
    list_res = client.get("/api/v1/developer/keys", headers=headers)
    assert list_res.status_code == 200
    keys = list_res.json()
    assert len(keys) >= 1
    found_key = next((k for k in keys if k["id"] == key_id), None)
    assert found_key is not None
    assert "secret_key" not in found_key or found_key.get("secret_key") is None
    assert found_key["masked_key"].startswith("lon_live_")

    # 3. Authenticate against network tools using the developer secret key
    tool_res = client.post(
        "/api/v1/tools/ip-lookup",
        json={"query": "1.1.1.1"},
        headers={"X-API-Key": secret_key},
    )
    assert tool_res.status_code == 200
    assert tool_res.json()["query"] == "1.1.1.1"

    # 4. Revoke/delete key
    del_res = client.delete(f"/api/v1/developer/keys/{key_id}", headers=headers)
    assert del_res.status_code == 204

    # 5. Tool call with revoked key must fail with 401
    tool_fail_res = client.post(
        "/api/v1/tools/ip-lookup",
        json={"query": "1.1.1.1"},
        headers={"X-API-Key": secret_key},
    )
    assert tool_fail_res.status_code == 401
