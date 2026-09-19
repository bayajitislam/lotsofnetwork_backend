import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from app.database import Base


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), index=True, nullable=False)
    plan_id = Column(String(36), ForeignKey("plans.id"), nullable=False)
    stripe_customer_id = Column(String(100), nullable=True, index=True)
    stripe_subscription_id = Column(String(100), nullable=True, index=True)
    status = Column(String(30), nullable=False, default="active")
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
