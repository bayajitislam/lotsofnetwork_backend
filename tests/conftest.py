"""
conftest.py — shared pytest fixtures for the LotsofNetwork backend test suite.

This file is loaded by pytest before any test module. It:
  1. Forces ENV=test and sets a SQLite DATABASE_URL so tests never need
     a real PostgreSQL connection.
  2. Resets the lazy engine globals so the test DB is always fresh.
  3. Creates all tables once per test session.
  4. Exposes `db_session` and `clean_db` fixtures used by individual tests.
"""
import pytest
from app.config import settings

# ---------------------------------------------------------------------------
# 1. Set ENV and DATABASE_URL BEFORE any module-level engine creation.
#    This must happen at module scope (not inside a fixture) so it runs
#    before test collection imports app.main / app.database.
# ---------------------------------------------------------------------------
settings.ENV = "test"
settings.DATABASE_URL = "sqlite:///./test_lotsofnetwork.db"
# Test-only JWT secrets — never used in production
settings.SECRET_KEY = "test-secret-key-must-be-at-least-32-chars-long-for-hmac-sha256!"
settings.REFRESH_SECRET_KEY = "test-refresh-secret-key-must-be-at-least-32-chars-long-for-hmac!"
settings.ADMIN_EMAILS = "realbayajitislam@gmail.com,contact@bayajitislam.com"
settings.CORS_ORIGINS = "http://localhost:3000"

# Reset lazy engine globals so the new URL is picked up.
import app.database as _db_module
_db_module._engine = None
_db_module._SessionLocal = None

from app.database import Base, get_engine, SessionLocal
from app.models import user, api_key, audit_log, campaign, article, tool_run, crash_log, plan, subscription  # noqa: F401 — register models


# ---------------------------------------------------------------------------
# 2. Create all tables once for the whole test session.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def create_tables():
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    yield
    # Optional: drop all tables after the full session (keep for debugging)
    # Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Ensure in-memory rate stores are cleared before and after each test."""
    from app.api.v1.tools import reset_rate_limit_stores
    reset_rate_limit_stores()
    yield
    reset_rate_limit_stores()


# ---------------------------------------------------------------------------
# 3. Shared clean-slate fixture — used by tests that need an empty DB.
#    Tests that already have their own `clean_db` fixture are unaffected.
# ---------------------------------------------------------------------------
@pytest.fixture
def clean_tables():
    """Truncate all tables before and after a test."""
    from app.models.user import User
    from app.models.api_key import ApiKey
    from app.models.audit_log import AuditLog
    from app.models.tool_run import ToolRun
    from app.models.crash_log import CrashLog
    from app.models.campaign import Campaign
    from app.models.article import Article
    from app.models.category import Category
    from app.models.tag import Tag

    _tables_to_clear = [AuditLog, ApiKey, ToolRun, CrashLog, Article, Campaign, Category, Tag, User]

    db = SessionLocal()
    try:
        for model in _tables_to_clear:
            db.query(model).delete()
        db.commit()
    finally:
        db.close()

    yield

    db = SessionLocal()
    try:
        for model in _tables_to_clear:
            db.query(model).delete()
        db.commit()
    finally:
        db.close()
