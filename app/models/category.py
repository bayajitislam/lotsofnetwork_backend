import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime
from app.database import Base


class Category(Base):
    __tablename__ = "categories"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(80), unique=True, nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    color = Column(String(20), default="#7c3aed", nullable=False)  # Hex color code for badges
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
