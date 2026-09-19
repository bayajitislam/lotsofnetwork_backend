import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime
from app.database import Base


class Plan(Base):
    __tablename__ = "plans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(80), nullable=False)
    slug = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    monthly_limit = Column(Integer, nullable=False, default=1000)
    rate_limit_rpm = Column(Integer, nullable=False, default=60)
    price_cents = Column(Integer, nullable=False, default=0)
    stripe_price_id = Column(String(100), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
