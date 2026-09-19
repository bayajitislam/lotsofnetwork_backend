import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, Text, DateTime
from app.database import Base


class CrashLog(Base):
    __tablename__ = "crash_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    service = Column(String(100), nullable=False)
    error_type = Column(String(100), nullable=False)
    message = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False, default="MEDIUM")  # HIGH, MEDIUM, LOW
    stack_trace = Column(Text, nullable=True)
    resolved = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
