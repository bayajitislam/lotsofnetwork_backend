import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.crash_log import CrashLog
from tests.test_telemetry_and_ads import get_test_admin_token

client = TestClient(app, raise_server_exceptions=False)


def test_unhandled_exception_global_handler():
    admin_token = get_test_admin_token()

    # Trigger diagnostic exception
    resp = client.post("/api/v1/admin/crash-logs/simulate", headers={"Authorization": f"Bearer {admin_token}"})
    assert resp.status_code == 500
    data = resp.json()
    assert "error_id" in data
    # Security check: error_type should NOT be leaked in public 500 response
    assert "error_type" not in data
    crash_id = data["error_id"]

    # Verify CrashLog was saved to database with internal details
    db = SessionLocal()
    crash = db.query(CrashLog).filter(CrashLog.id == crash_id).first()
    assert crash is not None
    assert crash.error_type == "RuntimeError"
    assert crash.severity == "HIGH"
    assert "Diagnostic unhandled exception" in crash.message
    assert crash.resolved is False
    db.close()

    # Verify /crash-logs lists the new crash
    list_resp = client.get("/api/v1/admin/crash-logs", headers={"Authorization": f"Bearer {admin_token}"})
    assert list_resp.status_code == 200
    logs = list_resp.json()
    assert any(l["id"] == crash_id for l in logs)

    # Verify resolving crash log
    res_resp = client.patch(
        f"/api/v1/admin/crash-logs/{crash_id}/resolve",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"resolved": True}
    )
    assert res_resp.status_code == 200
    assert res_resp.json()["resolved"] is True
