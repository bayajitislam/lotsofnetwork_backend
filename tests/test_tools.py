import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_subnet_calculator():
    resp = client.post("/api/v1/tools/subnet-calculator", json={"cidr": "192.168.1.0/24"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["netmask"] == "255.255.255.0"
    assert data["network_address"] == "192.168.1.0"
    assert data["broadcast_address"] == "192.168.1.255"
    assert data["first_usable_ip"] == "192.168.1.1"
    assert data["last_usable_ip"] == "192.168.1.254"
    assert data["usable_hosts"] == 254
    assert data["ip_class"] == "Class C"
    assert data["is_private"] is True


def test_subnet_calculator_slash_30():
    resp = client.post("/api/v1/tools/subnet-calculator", json={"cidr": "10.0.0.0/30"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["usable_hosts"] == 2
    assert data["netmask"] == "255.255.255.252"
    assert data["first_usable_ip"] == "10.0.0.1"
    assert data["last_usable_ip"] == "10.0.0.2"


def test_ip_lookup():
    resp = client.post("/api/v1/tools/ip-lookup", json={"query": "1.1.1.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "1.1.1.1"
    assert data["is_valid"] is True
    assert data["version"] == 4


def test_dns_lookup():
    resp = client.post("/api/v1/tools/dns-lookup", json={"domain": "google.com", "record_type": "A"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "google.com"
    assert data["record_count"] >= 1
    assert any(r["record_type"] == "A" for r in data["records"])


def test_port_checker():
    # SSRF protection: private/loopback IPs must be rejected with 400
    resp_private = client.post("/api/v1/tools/port-checker", json={"host": "127.0.0.1", "ports": [80]})
    assert resp_private.status_code == 400, "Loopback IP must be rejected by SSRF protection"
    assert "private" in resp_private.json()["detail"].lower() or "reserved" in resp_private.json()["detail"].lower()

    resp_internal = client.post("/api/v1/tools/port-checker", json={"host": "192.168.1.1", "ports": [80]})
    assert resp_internal.status_code == 400, "RFC1918 private IP must be rejected by SSRF protection"

    # Public IP scan should be allowed
    resp = client.post("/api/v1/tools/port-checker", json={"host": "8.8.8.8", "ports": [53, 443]})
    assert resp.status_code == 200, f"Public IP should be scannable, got: {resp.json()}"
    data = resp.json()
    assert data["host"] == "8.8.8.8"
    assert data["scanned_ports_count"] == 2
    statuses = [r["status"] for r in data["results"]]
    assert all(s in ["open", "closed", "filtered", "error"] for s in statuses)
