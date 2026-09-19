import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    admin_id = Column(String(36), index=True, nullable=False)
    admin_email = Column(String(255), nullable=False)
    action = Column(String(100), index=True, nullable=False)  # e.g., "USER_DEACTIVATED", "SETTINGS_UPDATED"
    resource_type = Column(String(50), nullable=False)       # e.g., "user", "api_key", "ad_slot"
    resource_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)                    # JSON or readable description
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
