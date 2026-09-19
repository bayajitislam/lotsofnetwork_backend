import hashlib
import time
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.campaign import Campaign

router = APIRouter(prefix="/ads", tags=["Public Ad Serving & Telemetry"])

# In-memory deduplication cache: hash(ip + campaign_id) -> timestamp
# Prevents artificial inflation of impressions
_IMPRESSION_CACHE: Dict[str, float] = {}
DEDUP_WINDOW_SECONDS = 900  # 15 minutes


class AdServeResponse(BaseModel):
    id: str
    name: str
    sponsor: str
    target_url: str
    image_url: Optional[str] = None
    image_dimensions: Optional[str] = "728x90"
    slot: str
    impressions: int
    clicks: int
    status: str


class AdTrackResponse(BaseModel):
    campaign_id: str
    impressions: int
    clicks: int
    incremented: bool
    target_url: Optional[str] = None
    message: str


@router.get("/active", response_model=List[AdServeResponse], summary="Get active ad campaigns for public slots")
def get_active_ads(slot: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Campaign).filter(Campaign.status == "active")
    if slot:
        query = query.filter(Campaign.slot == slot)
    campaigns = query.all()
    return [
        AdServeResponse(
            id=c.id,
            name=c.name,
            sponsor=c.sponsor,
            target_url=c.target_url,
            image_url=c.image_url,
            image_dimensions=c.image_dimensions or "728x90",
            slot=c.slot,
            impressions=c.impressions,
            clicks=c.clicks,
            status=c.status,
        )
        for c in campaigns
    ]


@router.post("/{campaign_id}/impression", response_model=AdTrackResponse, summary="Record a verified ad impression")
async def record_ad_impression(campaign_id: str, request: Request, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Determine client IP
    client_ip = "127.0.0.1"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    elif request.client and request.client.host:
        client_ip = request.client.host

    ua = request.headers.get("User-Agent", "unknown")
    hash_key = hashlib.sha256(f"{client_ip}:{ua}:{campaign_id}".encode()).hexdigest()

    now = time.time()
    last_imp = _IMPRESSION_CACHE.get(hash_key)

    if last_imp and (now - last_imp) < DEDUP_WINDOW_SECONDS:
        return AdTrackResponse(
            campaign_id=camp.id,
            impressions=camp.impressions,
            clicks=camp.clicks,
            incremented=False,
            message="Impression already recorded for this session within 15 minutes.",
        )

    _IMPRESSION_CACHE[hash_key] = now
    camp.impressions += 1
    db.commit()
    db.refresh(camp)

    return AdTrackResponse(
        campaign_id=camp.id,
        impressions=camp.impressions,
        clicks=camp.clicks,
        incremented=True,
        message="Live verified ad impression recorded successfully.",
    )


@router.post("/{campaign_id}/click", response_model=AdTrackResponse, summary="Record verified ad click and return target URL")
async def record_ad_click(campaign_id: str, db: Session = Depends(get_db)):
    camp = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")

    camp.clicks += 1
    db.commit()
    db.refresh(camp)

    return AdTrackResponse(
        campaign_id=camp.id,
        impressions=camp.impressions,
        clicks=camp.clicks,
        incremented=True,
        target_url=camp.target_url,
        message="Live verified ad click recorded successfully.",
    )
