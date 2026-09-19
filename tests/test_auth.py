import pytest
import jwt
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app.models.user import User

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    # Clean up test database
    db = SessionLocal()
    db.query(User).delete()
    db.commit()
    db.close()

def generate_mock_google_token(email: str, name: str, sub: str):
    # Generates unsigned mock Google ID JWT for testing development auth fallback
    return jwt.encode({"email": email, "name": name, "sub": sub}, key="mock_secret", algorithm="HS256")

def test_google_auth_regular_user():
    token = generate_mock_google_token(
        email="developer@example.com",
        name="Jane Developer",
        sub="google_sub_12345"
    )
    response = client.post("/api/v1/auth/google", json={"credential": token})
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == "developer@example.com"
    assert data["user"]["role"] == "user"

    # Test /auth/me with regular user token
    access_token = data["access_token"]
    me_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "developer@example.com"

    # Verify regular user is denied access to admin routes
    admin_resp = client.get(
        "/api/v1/admin/stats",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert admin_resp.status_code == 403
    assert "Administrator privileges required" in admin_resp.json()["detail"]

def test_google_auth_admin_user():
    # Admin email in default settings: realbayajitislam@gmail.com
    admin_token = generate_mock_google_token(
        email="realbayajitislam@gmail.com",
        name="Bayajit Islam",
        sub="google_sub_admin_999"
    )
    response = client.post("/api/v1/auth/google", json={"credential": admin_token})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["user"]["role"] == "admin"

    access_token = data["access_token"]

    # Verify admin has access to /admin/stats
    admin_resp = client.get(
        "/api/v1/admin/stats",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert admin_resp.status_code == 200
    stats = admin_resp.json()
    assert stats["total_users"] >= 1
    assert stats["admin_users"] >= 1
    assert stats["status"] == "healthy"

    # Verify admin can list users
    users_resp = client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert users_resp.status_code == 200
    assert len(users_resp.json()) >= 1

def test_admin_deactivate_user():
    # 1. Create admin user
    admin_token = generate_mock_google_token("realbayajitislam@gmail.com", "Bayajit", "admin_1")
    admin_jwt = client.post("/api/v1/auth/google", json={"credential": admin_token}).json()["access_token"]

    # 2. Create regular user
    user_token = generate_mock_google_token("spammer@example.com", "Spammer", "user_bad_1")
    user_data = client.post("/api/v1/auth/google", json={"credential": user_token}).json()
    bad_user_id = user_data["user"]["id"]
    bad_jwt = user_data["access_token"]

    # 3. Admin deactivates regular user
    deactivate_resp = client.patch(
        f"/api/v1/admin/users/{bad_user_id}/status",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {admin_jwt}"}
    )
    assert deactivate_resp.status_code == 200
    assert deactivate_resp.json()["is_active"] is False

    # 4. Deactivated user tries to access /auth/me -> should be 403 Forbidden
    blocked_resp = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {bad_jwt}"}
    )
    assert blocked_resp.status_code == 403
    assert "deactivated" in blocked_resp.json()["detail"].lower()
