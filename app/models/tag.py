import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime
from app.database import Base


class Tag(Base):
    __tablename__ = "tags"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(50), unique=True, nullable=False)
    slug = Column(String(60), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
