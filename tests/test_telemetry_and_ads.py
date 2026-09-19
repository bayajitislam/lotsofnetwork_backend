import pytest
import jwt
from fastapi.testclient import TestClient
from app.config import settings
from app.main import app
from app.database import SessionLocal
from app.models.campaign import Campaign
from app.models.tool_run import ToolRun
from app.models.crash_log import CrashLog

settings.ENV = "test"
client = TestClient(app)


def get_test_admin_token():
    payload = {
        "email": "realbayajitislam@gmail.com",
        "name": "Bayajit Islam",
        "sub": "sub_admin_telemetry_test",
        "email_verified": True,
        "iss": "https://accounts.google.com"
    }
    mock_jwt = jwt.encode(payload, key="test-mock-secret-key-must-be-32-bytes-long!", algorithm="HS256")
    res = client.post("/api/v1/auth/google", json={"credential": mock_jwt})
    return res.json()["access_token"]


def test_tool_telemetry_recording_and_admin_retrieval():
    admin_token = get_test_admin_token()

    # 1. Run a tool (subnet-calculator)
    sub_res = client.post("/api/v1/tools/subnet-calculator", json={"cidr": "10.0.0.0/16"})
    assert sub_res.status_code == 200

    # 2. Check that ToolRun row was written to SQLite
    db = SessionLocal()
    runs = db.query(ToolRun).filter(ToolRun.tool_slug == "subnet-calculator").all()
    assert len(runs) >= 1
    assert runs[0].status == "success"
    assert runs[0].latency_ms >= 0.0
    db.close()

    # 3. Check /admin/telemetry reflects real database runs
    tel_res = client.get("/api/v1/admin/telemetry", headers={"Authorization": f"Bearer {admin_token}"})
    assert tel_res.status_code == 200
    telemetry = tel_res.json()
    assert len(telemetry) == 18  # Platform active engines

    sub_tool = next(t for t in telemetry if t["slug"] == "subnet-calculator")
    assert sub_tool["queries_per_hour"] >= 1
    assert sub_tool["status"] == "Operational"


def test_ad_campaign_impression_and_click_telemetry():
    admin_token = get_test_admin_token()

    # 1. Fetch campaigns from admin
    camps_res = client.get("/api/v1/admin/campaigns", headers={"Authorization": f"Bearer {admin_token}"})
    assert camps_res.status_code == 200
    campaigns = camps_res.json()
    assert len(campaigns) > 0
    target_camp = campaigns[0]
    camp_id = target_camp["id"]

    initial_impressions = target_camp["impressions"]
    initial_clicks = target_camp["clicks"]

    # 2. Record ad impression
    imp_res = client.post(f"/api/v1/ads/{camp_id}/impression", headers={"User-Agent": "Test-Imp-User-Agent-1"})
    assert imp_res.status_code == 200
    imp_data = imp_res.json()
    assert imp_data["incremented"] is True
    assert imp_data["impressions"] == initial_impressions + 1

    # 3. Duplicate impression should be deduplicated
    imp_res_dedup = client.post(f"/api/v1/ads/{camp_id}/impression", headers={"User-Agent": "Test-Imp-User-Agent-1"})
    assert imp_res_dedup.status_code == 200
    assert imp_res_dedup.json()["incremented"] is False

    # 4. Record ad click
    click_res = client.post(f"/api/v1/ads/{camp_id}/click")
    assert click_res.status_code == 200
    click_data = click_res.json()
    assert click_data["incremented"] is True
    assert click_data["clicks"] == initial_clicks + 1
    assert "target_url" in click_data


def test_crash_log_resolution_and_retrieval():
    admin_token = get_test_admin_token()

    # 1. Insert a crash log in DB
    db = SessionLocal()
    crash = CrashLog(
        service="Test Worker",
        error_type="TestException",
        message="Simulated test error",
        severity="HIGH",
        resolved=False,
    )
    db.add(crash)
    db.commit()
    crash_id = crash.id
    db.close()

    # 2. Retrieve crash logs from admin
    res = client.get("/api/v1/admin/crash-logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    logs = res.json()
    assert any(l["id"] == crash_id for l in logs)

    # 3. Resolve crash log
    patch_res = client.patch(
        f"/api/v1/admin/crash-logs/{crash_id}/resolve",
        json={"resolved": True},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["resolved"] is True
