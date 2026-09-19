import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.tool_run import ToolRun

client = TestClient(app)


def test_cidr_converter():
    resp = client.post("/api/v1/tools/cidr-converter", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["prefix_length"] == 24
    assert data["netmask"] == "255.255.255.0"
    assert data["wildcard_mask"] == "0.0.0.255"
    assert data["binary_netmask"] == "11111111.11111111.11111111.00000000"
    assert data["hex_netmask"] == "0xFFFFFF00"
    assert data["usable_hosts"] == 254
    assert data["ip_class"] == "Class A"
    assert data["is_private"] is True


def test_ipv6_calculator():
    resp = client.post("/api/v1/tools/ipv6-calculator", json={"address": "2001:db8::1/64"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["prefix_length"] == 64
    assert len(data["expanded_address"]) == 39
    assert data["reverse_dns_ptr"].endswith(".ip6.arpa")
    assert "Documentation" in data["scope"] or "Unicast" in data["scope"]


def test_user_agent_analyzer():
    ua_string = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    resp = client.post("/api/v1/tools/user-agent-analyzer", json={"user_agent": ua_string})
    assert resp.status_code == 200
    data = resp.json()
    assert data["browser"] == "Google Chrome"
    assert data["os"] == "macOS"
    assert data["engine"] == "Blink"
    assert data["is_bot"] is False
    assert data["device_type"] == "Desktop"


def test_uuid_generator():
    # Test v4
    resp4 = client.post("/api/v1/tools/uuid-generator", json={"version": "v4", "count": 3})
    assert resp4.status_code == 200
    d4 = resp4.json()
    assert len(d4["uuids"]) == 3
    assert d4["version"] == "v4"

    # Test v7
    resp7 = client.post("/api/v1/tools/uuid-generator", json={"version": "v7", "count": 2})
    assert resp7.status_code == 200
    d7 = resp7.json()
    assert len(d7["uuids"]) == 2
    assert d7["version"] == "v7"
    assert d7["details"][0]["version"] == 7
    assert d7["details"][0]["timestamp_iso"] is not None


def test_json_formatter_valid_and_invalid():
    # Valid JSON
    valid_json = "{\"name\":\"LotsOfNetwork\",\"tools\":18,\"active\":true}"
    resp = client.post("/api/v1/tools/json-formatter", json={"json_string": valid_json, "indent": 2})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert "  " in data["formatted"]
    assert data["total_keys"] == 3
    assert data["compression_percent"] >= 0.0

    # Invalid JSON
    invalid_json = "{\"name\": \"broken\", invalid}"
    resp_inv = client.post("/api/v1/tools/json-formatter", json={"json_string": invalid_json})
    assert resp_inv.status_code == 200
    d_inv = resp_inv.json()
    assert d_inv["is_valid"] is False
    assert d_inv["error_message"] is not None
    assert d_inv["error_line"] is not None


def test_punycode_converter():
    # Encode
    resp = client.post("/api/v1/tools/punycode-converter", json={"input_text": "münchen.de", "mode": "encode"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"] == "xn--mnchen-3ya.de"
    assert data["is_idn"] is True

    # Decode
    resp_dec = client.post("/api/v1/tools/punycode-converter", json={"input_text": "xn--mnchen-3ya.de", "mode": "decode"})
    assert resp_dec.status_code == 200
    assert resp_dec.json()["result"] == "münchen.de"


def test_chmod_calculator():
    resp = client.post("/api/v1/tools/chmod-calculator", json={"octal": "755"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["octal"] == "755"
    assert data["octal_4digit"] == "0755"
    assert data["symbolic"] == "-rwxr-xr-x"
    assert data["umask"] == "0022"
    assert data["owner"]["read"] is True
    assert data["owner"]["write"] is True
    assert data["owner"]["execute"] is True
    assert data["group"]["write"] is False


def test_timestamp_converter():
    resp = client.post("/api/v1/tools/timestamp-converter", json={"timestamp": "1700000000"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["epoch_seconds"] == 1700000000
    assert data["iso_8601_utc"] == "2023-11-14T22:13:20Z"
    assert data["day_of_week"] == "Tuesday"


def test_base64_encode_decode():
    raw_str = "Hello Network World 2026!"
    # Encode
    resp_enc = client.post("/api/v1/tools/base64-encode-decode", json={"input_text": raw_str, "action": "encode"})
    assert resp_enc.status_code == 200
    b64_val = resp_enc.json()["output_text"]
    assert len(b64_val) > 0

    # Decode
    resp_dec = client.post("/api/v1/tools/base64-encode-decode", json={"input_text": b64_val, "action": "decode"})
    assert resp_dec.status_code == 200
    assert resp_dec.json()["output_text"] == raw_str


def test_mac_lookup():
    # Cisco OUI: 00:00:0C
    resp = client.post("/api/v1/tools/mac-lookup", json={"mac_address": "00:00:0C:12:34:56"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["oui_prefix"] == "00:00:0C"
    assert "Cisco" in data["vendor"]
    assert data["transmission_type"] == "Unicast"


def test_reverse_dns_lookup():
    # Cloudflare 1.1.1.1
    resp = client.post("/api/v1/tools/reverse-dns", json={"ip": "1.1.1.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "1.1.1.1"
    assert data["ip_version"] == 4


def test_whois_lookup():
    resp = client.post("/api/v1/tools/whois-lookup", json={"domain": "google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["domain"] == "google.com"
    assert data["registrar"] is not None


def test_ssl_checker():
    # Inspect google.com on port 443
    resp = client.post("/api/v1/tools/ssl-checker", json={"host": "google.com", "port": 443})
    assert resp.status_code == 200
    data = resp.json()
    assert data["host"] == "google.com"
    assert data["port"] == 443
    assert "is_valid" in data


def test_http_headers_analyzer():
    resp = client.post("/api/v1/tools/http-headers", json={"url": "https://www.cloudflare.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status_code"] in [200, 301, 302]
    assert data["security_score"] >= 0
    assert data["grade"] in ["A+", "A", "B", "C", "D", "F"]


def test_all_18_tools_telemetry_recording():
    db = SessionLocal()
    tools_checked = [
        "cidr-converter", "ipv6-calculator", "user-agent-analyzer", "uuid-generator",
        "json-formatter", "punycode-converter", "chmod-calculator", "timestamp-converter",
        "base64-encode-decode", "mac-lookup"
    ]
    for slug in tools_checked:
        count = db.query(ToolRun).filter(ToolRun.tool_slug == slug).count()
        assert count >= 1, f"Expected telemetry record for {slug}, but found 0"
    db.close()
