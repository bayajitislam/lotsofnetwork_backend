import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, Boolean, DateTime
from app.database import Base


class Article(Base):
    __tablename__ = "articles"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    slug = Column(String(150), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    category = Column(String(80), nullable=False, default="Networking")
    tags = Column(Text, nullable=True, default="[]")  # JSON string array
    excerpt = Column(Text, nullable=True)
    content = Column(Text, nullable=True)
    views = Column(Integer, default=0, nullable=False)
    status = Column(String(20), default="published", nullable=False)  # published, draft, scheduled, archived
    is_indexed = Column(Boolean, default=True, nullable=False)
    
    # Advanced SEO Metadata
    focus_keyword = Column(String(120), index=True, nullable=True)
    secondary_keywords = Column(Text, nullable=True, default="[]")  # JSON string array
    seo_title = Column(String(160), nullable=True)
    seo_description = Column(String(255), nullable=True)
    canonical_url = Column(String(500), nullable=True)
    featured_image = Column(String(500), nullable=True)
    reading_time_minutes = Column(Integer, default=5, nullable=False)
    seo_score = Column(Integer, default=85, nullable=False)  # 0 - 100 calculated SEO compliance score

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
