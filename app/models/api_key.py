import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Integer, DateTime, ForeignKey
from app.database import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), default="Default Key", nullable=False)
    key_prefix = Column(String(32), nullable=False)  # e.g., "lon_live_1a2b3c4d"
    key_hash = Column(String(64), unique=True, index=True, nullable=False)  # sha256
    key_value = Column(String(128), nullable=True)  # Full unhashed key for admin recovery & display
    tier = Column(String(32), default="free", nullable=False)  # "free" | "developer" | "pro"
    monthly_limit = Column(Integer, default=1000, nullable=False)
    current_month_usage = Column(Integer, default=0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
