import pytest
import jwt
from fastapi.testclient import TestClient
from app.config import settings
from app.main import app
from app.database import SessionLocal
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog

settings.ENV = "test"
client = TestClient(app)


def get_test_admin_token():
    payload = {
        "email": "realbayajitislam@gmail.com",
        "name": "Bayajit Islam",
        "sub": "sub_admin_api_keys_test",
        "email_verified": True,
        "iss": "https://accounts.google.com"
    }
    mock_jwt = jwt.encode(payload, key="test-mock-secret-key-must-be-32-bytes-long!", algorithm="HS256")
    res = client.post("/api/v1/auth/google", json={"credential": mock_jwt})
    return res.json()["access_token"]


def test_list_and_create_api_key():
    token = get_test_admin_token()

    # 1. Create API key
    payload = {
        "name": "Test Integration Key",
        "tier": "developer",
        "monthly_limit": 25000,
    }
    res = client.post("/api/v1/admin/api-keys", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 201
    data = res.json()

    assert data["name"] == "Test Integration Key"
    assert data["tier"] == "developer"
    assert data["monthly_limit"] == 25000
    assert "secret_key" in data
    assert data["secret_key"].startswith("lon_live_")
    assert len(data["secret_key"]) > 20
    assert data["is_active"] is True
    assert data["key_value"] == data["secret_key"]

    key_id = data["id"]
    secret_key = data["secret_key"]

    # 2. List API keys
    list_res = client.get("/api/v1/admin/api-keys", headers={"Authorization": f"Bearer {token}"})
    assert list_res.status_code == 200
    keys = list_res.json()
    assert any(k["id"] == key_id for k in keys)

    # Key value is available for admin management
    target = next(k for k in keys if k["id"] == key_id)
    assert target["key_value"] == secret_key

    # 3. Check stats revenue is NOT artificially multiplied by $29
    stats_res = client.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {token}"})
    assert stats_res.status_code == 200
    assert stats_res.json()["api_revenue"] == 0.0  # Zero fake money!

    # 4. Test live tool authentication with the key
    # A. Valid key
    tool_res = client.post(
        "/api/v1/tools/ip-lookup",
        json={"query": "8.8.8.8"},
        headers={"X-API-Key": secret_key}
    )
    assert tool_res.status_code == 200
    assert tool_res.json()["ip"] == "8.8.8.8"

    # Verify usage was incremented in DB
    db = SessionLocal()
    saved_key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    assert saved_key.current_month_usage == 1
    assert saved_key.last_used_at is not None
    db.close()

    # B. Invalid key
    bad_res = client.post(
        "/api/v1/tools/ip-lookup",
        json={"query": "8.8.8.8"},
        headers={"X-API-Key": "lon_live_invalid_key_9999"}
    )
    assert bad_res.status_code == 401

    # C. Suspended key
    patch_res = client.patch(
        f"/api/v1/admin/api-keys/{key_id}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert patch_res.status_code == 200

    susp_res = client.post(
        "/api/v1/tools/ip-lookup",
        json={"query": "8.8.8.8"},
        headers={"X-API-Key": secret_key}
    )
    assert susp_res.status_code == 403

    # D. Delete API key
    del_res = client.delete(f"/api/v1/admin/api-keys/{key_id}", headers={"Authorization": f"Bearer {token}"})
    assert del_res.status_code == 200
