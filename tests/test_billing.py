import json
import jwt
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.database import SessionLocal
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.plan import Plan
from app.models.subscription import Subscription
from app.services.security import create_access_token

client = TestClient(app)


@pytest.fixture
def auth_user():
    db = SessionLocal()
    user = db.query(User).filter(User.email == "billing_dev@lotsofnetwork.com").first()
    if not user:
        user = User(
            email="billing_dev@lotsofnetwork.com",
            name="Billing Developer",
            google_id="billing_dev_sub_123",
            role="user",
            is_active=True,
            token_version=1,
            created_at=datetime.now(timezone.utc),
            last_login_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Ensure clean state for test user
    db.query(Subscription).filter(Subscription.user_id == user.id).delete()
    db.commit()

    token_claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "ver": user.token_version,
    }
    token = create_access_token(data=token_claims)
    user_id = user.id
    db.close()
    return {"token": token, "user_id": user_id}


def test_get_billing_plans():
    resp = client.get("/api/v1/billing/plans")
    assert resp.status_code == 200
    plans = resp.json()
    assert len(plans) >= 3
    slugs = [p["slug"] for p in plans]
    assert "free" in slugs
    assert "pro" in slugs
    assert "enterprise" in slugs

    free_plan = next(p for p in plans if p["slug"] == "free")
    assert free_plan["monthly_limit"] == 1000
    assert free_plan["price_cents"] == 0

    pro_plan = next(p for p in plans if p["slug"] == "pro")
    assert pro_plan["monthly_limit"] == 50000
    assert pro_plan["price_cents"] == 2900


def test_get_user_subscription(auth_user):
    headers = {"Authorization": f"Bearer {auth_user['token']}"}
    resp = client.get("/api/v1/billing/subscription", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_id"] == auth_user["user_id"]
    assert data["plan"]["slug"] == "free"
    assert data["status"] == "active"


def test_checkout_when_billing_disabled(auth_user):
    headers = {"Authorization": f"Bearer {auth_user['token']}"}
    resp = client.post(
        "/api/v1/billing/checkout",
        headers=headers,
        json={"plan_slug": "pro"},
    )
    # When BILLING_ENABLED=False or stripe keys not configured, returns 503
    assert resp.status_code in (503, 400)


def test_stripe_webhook_flow(auth_user):
    import uuid
    db = SessionLocal()
    # Clean up and ensure user has an API key with default 1000 limit
    db.query(ApiKey).filter(ApiKey.user_id == auth_user["user_id"]).delete()
    db.commit()

    key = ApiKey(
        user_id=auth_user["user_id"],
        name="Developer Test Key",
        key_prefix="lon_live_12345678",
        key_hash=f"hash_for_test_{uuid.uuid4().hex}",
        monthly_limit=1000,
        current_month_usage=0,
        is_active=True,
        quota_reset_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db.add(key)
    db.commit()

    pro_plan = db.query(Plan).filter(Plan.slug == "pro").first()
    assert pro_plan is not None

    test_cust_id = f"cus_test_{uuid.uuid4().hex[:8]}"
    test_sub_id = f"sub_test_{uuid.uuid4().hex[:8]}"

    # Simulate checkout.session.completed webhook
    webhook_payload = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": auth_user["user_id"],
                "customer": test_cust_id,
                "subscription": test_sub_id,
                "metadata": {
                    "user_id": auth_user["user_id"],
                    "plan_id": pro_plan.id,
                    "plan_slug": "pro",
                },
            }
        },
    }

    resp = client.post(
        "/api/v1/billing/webhook",
        data=json.dumps(webhook_payload),
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 200

    # Verify user's ApiKey quota was automatically upgraded to pro_plan.monthly_limit (50,000)
    db.expire_all()
    updated_key = db.query(ApiKey).filter(ApiKey.user_id == auth_user["user_id"]).first()
    assert updated_key.monthly_limit == 50000

    # Simulate customer.subscription.deleted webhook (cancellation)
    cancel_payload = {
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "customer": test_cust_id,
                "status": "canceled",
            }
        },
    }

    resp_cancel = client.post(
        "/api/v1/billing/webhook",
        data=json.dumps(cancel_payload),
        headers={"Content-Type": "application/json"},
    )
    assert resp_cancel.status_code == 200

    # Verify user's ApiKey quota was downgraded back to free limit (1,000)
    db.expire_all()
    reverted_key = db.query(ApiKey).filter(ApiKey.user_id == auth_user["user_id"]).first()
    assert reverted_key.monthly_limit == 1000

    db.close()


@pytest.fixture
def auth_admin():
    db = SessionLocal()
    admin = db.query(User).filter(User.email == "billing_admin@lotsofnetwork.com").first()
    if not admin:
        admin = User(
            email="billing_admin@lotsofnetwork.com",
            name="Billing Administrator",
            google_id="billing_admin_sub_999",
            role="admin",
            is_active=True,
            token_version=1,
            created_at=datetime.now(timezone.utc),
            last_login_at=datetime.now(timezone.utc),
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)

    token_claims = {
        "sub": admin.id,
        "email": admin.email,
        "role": admin.role,
        "ver": admin.token_version,
    }
    token = create_access_token(data=token_claims)
    admin_id = admin.id
    db.close()
    return {"token": token, "admin_id": admin_id}


def test_admin_subscriptions_flow(auth_admin, auth_user):
    headers = {"Authorization": f"Bearer {auth_admin['token']}"}

    # 1. Ensure user has an active key
    db = SessionLocal()
    import uuid
    db.query(ApiKey).filter(ApiKey.user_id == auth_user["user_id"]).delete()
    db.commit()
    key = ApiKey(
        user_id=auth_user["user_id"],
        name="Admin Managed Key",
        key_prefix="lon_live_adminmanage",
        key_hash=f"hash_admin_manage_{uuid.uuid4().hex}",
        monthly_limit=1000,
        current_month_usage=0,
        is_active=True,
        quota_reset_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db.add(key)
    db.commit()
    db.close()

    # 2. List subscriptions via Admin API
    resp = client.get("/api/v1/admin/subscriptions", headers=headers)
    assert resp.status_code == 200
    subs = resp.json()
    assert isinstance(subs, list)

    # 3. Admin overrides user's plan to 'enterprise'
    override_resp = client.patch(
        f"/api/v1/admin/subscriptions/{auth_user['user_id']}",
        headers=headers,
        json={"plan_slug": "enterprise", "reason": "VIP customer trial"},
    )
    assert override_resp.status_code == 200
    override_data = override_resp.json()
    assert override_data["plan_slug"] == "enterprise"
    assert override_data["monthly_limit"] == 500000

    # Verify user's API key quota was synced to 500,000!
    db = SessionLocal()
    synced_key = db.query(ApiKey).filter(ApiKey.user_id == auth_user["user_id"]).first()
    assert synced_key.monthly_limit == 500000
    assert synced_key.tier == "enterprise"
    db.close()

    # 4. List admin plans
    plans_resp = client.get("/api/v1/admin/plans", headers=headers)
    assert plans_resp.status_code == 200
    plans = plans_resp.json()
    assert len(plans) >= 3

