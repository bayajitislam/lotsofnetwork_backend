from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

Base = declarative_base()

# ---------------------------------------------------------------------------
# Lazy engine — created on first access so that:
#   1. Tests can override settings.ENV / settings.DATABASE_URL before the
#      engine is instantiated.
#   2. The server doesn't blow up at import time if DATABASE_URL is empty
#      (validate_production_secrets() in main.py catches that at startup).
# ---------------------------------------------------------------------------
_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        db_url = settings.DATABASE_URL
        from pathlib import Path
        root_dir = Path(__file__).resolve().parent.parent
        sqlite_url = f"sqlite:///{root_dir / 'lotsofnetwork.db'}"

        if not db_url:
            raise RuntimeError("DATABASE_URL is not configured. PostgreSQL connection string is required.")

        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
        elif db_url.startswith("postgresql://") and not any(
            driver in db_url for driver in ("+psycopg", "+psycopg2", "+asyncpg", "+pg8000")
        ):
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

        connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
        pool_kwargs = {}
        if not db_url.startswith("sqlite"):
            pool_kwargs = {
                "pool_size": 10,
                "max_overflow": 20,
                "pool_pre_ping": True,
            }
        _engine = create_engine(db_url, connect_args=connect_args, **pool_kwargs)
        with _engine.connect() as conn:
            pass
        print(f"[DATABASE] Successfully connected to PostgreSQL: {db_url.split('@')[-1]}")
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_get_engine())
    return _SessionLocal


@property  # type: ignore[misc]
def engine(_):
    return _get_engine()


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
