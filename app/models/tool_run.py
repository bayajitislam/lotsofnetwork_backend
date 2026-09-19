import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, Index
from app.database import Base


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tool_slug = Column(String(80), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    latency_ms = Column(Float, nullable=False, default=0.0)
    status = Column(String(20), nullable=False, default="success")  # success, error
    error_message = Column(String(500), nullable=True)
    client_ip = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("idx_tool_runs_slug_created", "tool_slug", "created_at"),
    )
