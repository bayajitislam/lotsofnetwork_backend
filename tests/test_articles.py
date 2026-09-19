import pytest
import jwt
from fastapi.testclient import TestClient
from app.config import settings
from app.main import app

settings.ENV = "test"
client = TestClient(app)


def get_test_admin_token():
    payload = {
        "email": "realbayajitislam@gmail.com",
        "name": "Bayajit Islam",
        "sub": "sub_admin_articles_test",
        "email_verified": True,
        "iss": "https://accounts.google.com"
    }
    mock_jwt = jwt.encode(payload, key="test-mock-secret-key-must-be-32-bytes-long!", algorithm="HS256")
    res = client.post("/api/v1/auth/google", json={"credential": mock_jwt})
    return res.json()["access_token"]


def test_get_blog_posts():
    # 1. Primary endpoint: /api/v1/blog
    response = client.get("/api/v1/blog")
    assert response.status_code == 200
    posts = response.json()
    assert isinstance(posts, list)
    assert len(posts) > 0
    assert "slug" in posts[0]
    assert "views" in posts[0]

    # 2. Legacy alias: /api/v1/articles
    legacy_res = client.get("/api/v1/articles")
    assert legacy_res.status_code == 200
    assert len(legacy_res.json()) == len(posts)


def test_get_blog_post_by_slug():
    # 1. Primary endpoint: /api/v1/blog/{slug}
    response = client.get("/api/v1/blog/what-is-a-subnet")
    assert response.status_code == 200
    art = response.json()
    assert art["slug"] == "what-is-a-subnet"
    assert "views" in art

    # 2. Legacy alias: /api/v1/articles/{slug}
    legacy_res = client.get("/api/v1/articles/what-is-a-subnet")
    assert legacy_res.status_code == 200
    assert legacy_res.json()["slug"] == "what-is-a-subnet"


def test_track_blog_view_and_deduplication():
    # 1. Get initial views via /api/v1/blog/{slug}
    initial_res = client.get("/api/v1/blog/what-is-a-subnet")
    assert initial_res.status_code == 200
    initial_views = initial_res.json()["views"]

    # 2. Track view with a unique test client
    headers = {"User-Agent": "Pytest-Blog-Telemetry-Tester-1"}
    view_res = client.post("/api/v1/blog/what-is-a-subnet/view", headers=headers)
    assert view_res.status_code == 200
    data = view_res.json()
    assert data["incremented"] is True
    assert data["views"] == initial_views + 1

    # 3. Second rapid request from same client should be deduplicated
    view_res_dedup = client.post("/api/v1/blog/what-is-a-subnet/view", headers=headers)
    assert view_res_dedup.status_code == 200
    data_dedup = view_res_dedup.json()
    assert data_dedup["incremented"] is False
    assert data_dedup["views"] == initial_views + 1


def test_reset_all_article_views():
    token = get_test_admin_token()
    # Call reset all views endpoint
    response = client.post(
        "/api/v1/admin/articles/reset-all-views",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["count"] > 0

    # Verify article views are indeed 0
    art_res = client.get("/api/v1/blog/what-is-a-subnet")
    assert art_res.status_code == 200
    assert art_res.json()["views"] == 0
