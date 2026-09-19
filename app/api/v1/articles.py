import hashlib
import json
import time
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.article import Article

# Primary router for /api/v1/blog (1:1 parity with Next.js /blog/[slug] and Google SEO indexed URLs)
router = APIRouter(prefix="/blog", tags=["Public Blog & Telemetry"])

# Backwards-compatible legacy alias for /api/v1/articles
legacy_router = APIRouter(prefix="/articles", tags=["Legacy Articles Alias"])

# In-memory deduplication cache: hash(ip + slug) -> timestamp
# Prevents spamming pageviews if a user refreshes within 15 minutes (900 seconds)
_VIEW_CACHE: Dict[str, float] = {}
DEDUP_WINDOW_SECONDS = 900


class PublicArticleResponse(BaseModel):
    id: str
    slug: str
    title: str
    category: str
    tags: List[str]
    excerpt: Optional[str] = None
    content: Optional[str] = None
    views: int
    focus_keyword: Optional[str] = None
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None
    canonical_url: Optional[str] = None
    featured_image: Optional[str] = None
    reading_time_minutes: int
    published_at: str


class ViewTrackResponse(BaseModel):
    slug: str
    views: int
    incremented: bool
    message: str


def _serialize_article(a: Article) -> PublicArticleResponse:
    tags_list = []
    if a.tags:
        try:
            tags_list = json.loads(a.tags)
        except Exception:
            tags_list = []
    return PublicArticleResponse(
        id=a.id,
        slug=a.slug,
        title=a.title,
        category=a.category,
        tags=tags_list,
        excerpt=a.excerpt,
        content=a.content,
        views=a.views,
        focus_keyword=a.focus_keyword,
        seo_title=a.seo_title,
        seo_description=a.seo_description,
        canonical_url=a.canonical_url,
        featured_image=a.featured_image,
        reading_time_minutes=a.reading_time_minutes,
        published_at=a.created_at.isoformat(),
    )


@router.get("", response_model=List[PublicArticleResponse], summary="List published blog posts")
@legacy_router.get("", response_model=List[PublicArticleResponse], include_in_schema=False)
def get_published_blog_posts(
    category: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Article).filter(Article.status == "published")
    if category and category != "all":
        query = query.filter(Article.category == category)
    articles = query.order_by(Article.views.desc()).all()
    return [_serialize_article(a) for a in articles]


@router.get("/{slug}", response_model=PublicArticleResponse, summary="Get single blog post by slug")
@legacy_router.get("/{slug}", response_model=PublicArticleResponse, include_in_schema=False)
def get_blog_post_by_slug(slug: str, db: Session = Depends(get_db)):
    art = db.query(Article).filter(Article.slug == slug.lower()).first()
    if not art:
        raise HTTPException(status_code=404, detail="Blog post not found")
    return _serialize_article(art)


@router.post("/{slug}/view", response_model=ViewTrackResponse, summary="Record a live verified blog pageview")
@legacy_router.post("/{slug}/view", response_model=ViewTrackResponse, include_in_schema=False)
async def track_blog_view(slug: str, request: Request, db: Session = Depends(get_db)):
    """
    Live real-time pageview telemetry for blog posts.
    Deduplicates page refreshes from the same client IP/UA within 15 minutes.
    """
    art = db.query(Article).filter(Article.slug == slug.lower()).first()
    if not art:
        raise HTTPException(status_code=404, detail="Blog post not found")

    # Determine client identity hash
    client_ip = "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif request.client and request.client.host:
        client_ip = request.client.host

    ua = request.headers.get("User-Agent", "unknown")
    hash_key = hashlib.sha256(f"{client_ip}:{ua}:{slug}".encode()).hexdigest()

    now = time.time()
    last_view = _VIEW_CACHE.get(hash_key)

    # Check if duplicate refresh within dedup window
    if last_view and (now - last_view) < DEDUP_WINDOW_SECONDS:
        return ViewTrackResponse(
            slug=art.slug,
            views=art.views,
            incremented=False,
            message="View already recorded for this session within 15-minute window.",
        )

    # Record new verified live view
    _VIEW_CACHE[hash_key] = now
    art.views += 1
    db.commit()
    db.refresh(art)

    # Clean up cache older than 1 hour to prevent memory bloat
    if len(_VIEW_CACHE) > 5000:
        cutoff = now - 3600
        for k in list(_VIEW_CACHE.keys()):
            if _VIEW_CACHE[k] < cutoff:
                del _VIEW_CACHE[k]

    return ViewTrackResponse(
        slug=art.slug,
        views=art.views,
        incremented=True,
        message="Live verified view recorded successfully.",
    )
