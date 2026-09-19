import os
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from alembic import context

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import settings
from app.database import Base, get_engine
# Import all models so that Base.metadata contains all model definitions
from app.models import user, api_key, audit_log, campaign, article, tool_run, crash_log

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_normalized_url() -> str:
    db_url = settings.DATABASE_URL
    if not db_url:
        from pathlib import Path
        root_dir = Path(__file__).resolve().parent.parent
        db_url = f"sqlite:///{root_dir / 'lotsofnetwork.db'}"

    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif db_url.startswith("postgresql://") and not any(
        driver in db_url for driver in ("+psycopg", "+psycopg2", "+asyncpg", "+pg8000")
    ):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return db_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_normalized_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using the app's SQLAlchemy engine."""
    connectable = get_engine()

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
