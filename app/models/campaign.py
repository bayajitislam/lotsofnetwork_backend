import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, DateTime
from app.database import Base


class Campaign(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(120), nullable=False)
    sponsor = Column(String(80), nullable=False)
    target_url = Column(String(500), nullable=False)
    image_url = Column(String(1000), nullable=True)  # Ad banner creative URL or local upload path
    image_dimensions = Column(String(50), nullable=True, default="728x90")  # Standard ad size: 728x90, 300x250, 300x600, etc.
    slot = Column(String(50), nullable=False, default="tool_header")
    impressions = Column(Integer, default=0, nullable=False)
    clicks = Column(Integer, default=0, nullable=False)
    conversions = Column(Integer, default=0, nullable=False)  # Verified sales/purchases
    revenue = Column(Float, default=0.0, nullable=False)      # Confirmed affiliate payout
    payout_type = Column(String(30), default="affiliate_cpa", nullable=False)  # affiliate_cpa, cpc, cpm
    target_impressions = Column(Integer, default=50000, nullable=False)
    status = Column(String(20), default="active", nullable=False)  # active, paused, completed
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
