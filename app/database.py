from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

Base = declarative_base()

# ---------------------------------------------------------------------------
# Lazy engine — created on first access so that:
#   1. Tests can override settings.DATABASE_URL before the engine is built.
#   2. The server doesn't blow up at import time if DATABASE_URL is empty
#      (validate_production_secrets() in main.py catches that at startup).
# ---------------------------------------------------------------------------
_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        db_url = settings.DATABASE_URL

        if not db_url:
            raise RuntimeError(
                "DATABASE_URL is not configured. "
                "Set a PostgreSQL connection string in your .env file."
            )

        # Normalise legacy postgres:// and bare postgresql:// → postgresql+psycopg://
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif db_url.startswith("postgresql://") and not any(
            driver in db_url for driver in ("+psycopg", "+psycopg2", "+asyncpg", "+pg8000")
        ):
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

        _engine = create_engine(
            db_url,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
        )
        with _engine.connect() as conn:
            pass
        print(f"[DATABASE] Connected to PostgreSQL: {db_url.split('@')[-1]}")
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_get_engine())
    return _SessionLocal


# Public surface used throughout the app
def get_engine():
    return _get_engine()


def get_db():
    SessionLocal = _get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Expose SessionLocal as a callable that always uses the current engine
class _LazySessionLocal:
    """Drop-in replacement for sessionmaker instance used in telemetry helpers."""
    def __call__(self):
        return _get_session_factory()()


SessionLocal = _LazySessionLocal()
