import pytest
import jwt
from fastapi.testclient import TestClient
from app.config import settings
from app.main import app
from app.database import Base, get_engine, SessionLocal
from app.models.user import User
from app.models.audit_log import AuditLog

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.create_all(bind=get_engine())
    db = SessionLocal()
    db.query(AuditLog).delete()
    db.query(User).delete()
    db.commit()
    db.close()
    yield
    db = SessionLocal()
    db.query(AuditLog).delete()
    db.query(User).delete()
    db.commit()
    db.close()


def generate_mock_google_token(email: str, name: str, sub: str, email_verified: bool = True):
    payload = {
        "email": email,
        "name": name,
        "sub": sub,
        "email_verified": email_verified,
        "iss": "https://accounts.google.com"
    }
    return jwt.encode(payload, key="test-mock-secret-key-must-be-32-bytes-long!", algorithm="HS256")


def test_google_auth_regular_user():
    token = generate_mock_google_token("developer@example.com", "Jane Dev", "sub_101")
    response = client.post("/api/v1/auth/google", json={"credential": token})
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "developer@example.com"
    assert data["user"]["role"] == "user"

    # User can access /auth/me
    access_token = data["access_token"]
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "developer@example.com"

    # User is forbidden from admin routes
    admin_resp = client.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {access_token}"})
    assert admin_resp.status_code == 403


def test_google_auth_admin_user():
    admin_token = generate_mock_google_token("realbayajitislam@gmail.com", "Bayajit Islam", "sub_admin_01")
    response = client.post("/api/v1/auth/google", json={"credential": admin_token})
    assert response.status_code == 200
    data = response.json()
    assert data["user"]["role"] == "admin"

    access_token = data["access_token"]
    admin_resp = client.get("/api/v1/admin/stats", headers={"Authorization": f"Bearer {access_token}"})
    assert admin_resp.status_code == 200
    stats = admin_resp.json()
    assert stats["admin_users"] == 1
    assert stats["status"] == "healthy"


def test_refresh_token_lifecycle():
    token = generate_mock_google_token("refresh_test@example.com", "Refresh Tester", "sub_refresh_01")
    auth_data = client.post("/api/v1/auth/google", json={"credential": token}).json()
    refresh_token = auth_data["refresh_token"]

    refresh_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 200, refresh_resp.text
    new_access_token = refresh_resp.json()["access_token"]

    # Verify new access token functions
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_access_token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "refresh_test@example.com"


def test_global_logout_revocation():
    token = generate_mock_google_token("logout_test@example.com", "Logout Tester", "sub_logout_01")
    auth_data = client.post("/api/v1/auth/google", json={"credential": token}).json()
    access_token = auth_data["access_token"]
    refresh_token = auth_data["refresh_token"]

    # 1. Call logout
    logout_resp = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access_token}"})
    assert logout_resp.status_code == 200

    # 2. Previous access token must now be rejected
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access_token}"})
    assert me_resp.status_code == 401
    assert "revoked" in me_resp.json()["detail"].lower()

    # 3. Previous refresh token must also be rejected
    refresh_resp = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_resp.status_code == 401
    assert "revoked" in refresh_resp.json()["detail"].lower()


def test_dynamic_role_demotion():
    # User originally signs in as admin
    admin_token = generate_mock_google_token("contact@bayajitislam.com", "Bayajit Contact", "sub_contact_01")
    auth_data = client.post("/api/v1/auth/google", json={"credential": admin_token}).json()
    assert auth_data["user"]["role"] == "admin"

    # Simulate removing email from admin whitelist
    original_whitelist = settings.ADMIN_EMAILS
    try:
        settings.ADMIN_EMAILS = "realbayajitislam@gmail.com"  # Removed contact@bayajitislam.com
        re_login = client.post("/api/v1/auth/google", json={"credential": admin_token}).json()
        assert re_login["user"]["role"] == "user"  # Correctly demoted to user
    finally:
        settings.ADMIN_EMAILS = original_whitelist


def test_admin_audit_trail_recorded():
    # 1. Admin login
    admin_token = generate_mock_google_token("realbayajitislam@gmail.com", "Bayajit Islam", "sub_admin_02")
    admin_jwt = client.post("/api/v1/auth/google", json={"credential": admin_token}).json()["access_token"]

    # 2. Regular user signup
    user_token = generate_mock_google_token("badactor@example.com", "Bad Actor", "sub_bad_01")
    bad_user = client.post("/api/v1/auth/google", json={"credential": user_token}).json()["user"]

    # 3. Admin deactivates user
    deact_resp = client.patch(
        f"/api/v1/admin/users/{bad_user['id']}/status",
        json={"is_active": False, "reason": "Violated terms of service"},
        headers={"Authorization": f"Bearer {admin_jwt}"}
    )
    assert deact_resp.status_code == 200

    # 4. Check audit log endpoint
    audit_resp = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {admin_jwt}"})
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    assert len(logs) >= 1
    assert logs[0]["action"] == "USER_DEACTIVATED"
    assert logs[0]["admin_email"] == "realbayajitislam@gmail.com"
    assert logs[0]["resource_id"] == bad_user["id"]


def test_unverified_email_rejected():
    # Token with email_verified: False
    unverified_token = generate_mock_google_token(
        "realbayajitislam@gmail.com",
        "Imposter",
        "sub_imposter_01",
        email_verified=False
    )
    resp = client.post("/api/v1/auth/google", json={"credential": unverified_token})
    assert resp.status_code == 400
    assert "not verified" in resp.json()["detail"].lower()


def test_refresh_token_sliding_window():
    # 1. Sign in as admin
    token = generate_mock_google_token("realbayajitislam@gmail.com", "Bayajit Islam", "sub_refresh_test")
    res = client.post("/api/v1/auth/google", json={"credential": token})
    assert res.status_code == 200
    auth_data = res.json()
    first_access = auth_data["access_token"]
    first_refresh = auth_data["refresh_token"]

    # 2. Exchange refresh token for fresh access token and renewed sliding refresh token
    ref_res = client.post("/api/v1/auth/refresh", json={"refresh_token": first_refresh})
    assert ref_res.status_code == 200
    ref_data = ref_res.json()
    assert "access_token" in ref_data
    assert "refresh_token" in ref_data
    assert ref_data["access_token"] != ""
    assert ref_data["refresh_token"] != ""

    # 3. Use new access token to query /me
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {ref_data['access_token']}"})
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "admin"


def test_developer_login_disabled_in_production():
    original_env = settings.ENV
    try:
        settings.ENV = "production"
        resp = client.post("/api/v1/auth/developer-login", json={"email": "attacker@example.com"})
        assert resp.status_code == 403
        assert "disabled in production" in resp.json()["detail"].lower()
    finally:
        settings.ENV = original_env


def test_set_cookies_requires_valid_token():
    # 1. Bogus access token must be rejected
    resp = client.post("/api/v1/auth/set-cookies", json={
        "access_token": "forged.token.payload",
        "refresh_token": "forged.refresh.payload"
    })
    assert resp.status_code == 401
    assert "invalid" in resp.json()["detail"].lower() or "expired" in resp.json()["detail"].lower()


def test_set_cookies_successful_with_valid_token():
    # 1. Obtain legitimate tokens
    token = generate_mock_google_token("cookie_test@example.com", "Cookie Tester", "sub_cookie_01")
    auth_data = client.post("/api/v1/auth/google", json={"credential": token}).json()
    access_token = auth_data["access_token"]
    refresh_token = auth_data["refresh_token"]

    # 2. Call set-cookies with genuine token
    resp = client.post("/api/v1/auth/set-cookies", json={
        "access_token": access_token,
        "refresh_token": refresh_token,
    })
    assert resp.status_code == 200
    assert "access_token" in resp.cookies
    assert "refresh_token" in resp.cookies


def test_health_check_database_probe():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"


def test_validate_production_secrets_checks_stripe_when_billing_enabled():
    original_billing = settings.BILLING_ENABLED
    original_stripe_sec = settings.STRIPE_SECRET_KEY
    original_stripe_wh = settings.STRIPE_WEBHOOK_SECRET
    original_env = settings.ENV

    try:
        settings.ENV = "production"
        settings.BILLING_ENABLED = True
        settings.STRIPE_SECRET_KEY = ""
        settings.STRIPE_WEBHOOK_SECRET = ""

        with pytest.raises(ValueError) as excinfo:
            settings.validate_production_secrets()
        assert "STRIPE_SECRET_KEY" in str(excinfo.value)
        assert "STRIPE_WEBHOOK_SECRET" in str(excinfo.value)
    finally:
        settings.ENV = original_env
        settings.BILLING_ENABLED = original_billing
        settings.STRIPE_SECRET_KEY = original_stripe_sec
        settings.STRIPE_WEBHOOK_SECRET = original_stripe_wh

