import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.plan import Plan
from app.models.subscription import Subscription
from app.api.deps import get_current_user
from app.schemas.api_key import ApiKeyResponse, ApiKeyCreateResponse
from app.api.v1.billing import ensure_default_plans

router = APIRouter(prefix="/developer", tags=["Developer Portal"])


class DeveloperKeyCreateRequest(BaseModel):
    name: str = Field(default="Primary Developer Key", min_length=2, max_length=128)


@router.get("/keys", response_model=List[ApiKeyResponse], summary="List developer API keys")
def list_developer_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns all API keys belonging to the currently authenticated developer."""
    keys = (
        db.query(ApiKey)
        .filter(ApiKey.user_id == current_user.id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )
    results = []
    for k in keys:
        results.append(
            ApiKeyResponse(
                id=k.id,
                user_id=k.user_id,
                user_email=current_user.email,
                user_name=current_user.name,
                name=k.name,
                key_prefix=k.key_prefix,
                masked_key=f"{k.key_prefix}••••••••••••",
                tier=k.tier,
                monthly_limit=k.monthly_limit,
                rate_limit_rpm=k.rate_limit_rpm,
                current_month_usage=k.current_month_usage,
                is_active=k.is_active,
                created_at=k.created_at,
                last_used_at=k.last_used_at,
            )
        )
    return results


@router.post(
    "/keys",
    response_model=ApiKeyCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new developer API key",
)
def create_developer_key(
    payload: DeveloperKeyCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generates a cryptographically secure developer API key linked to the user's active subscription tier."""
    ensure_default_plans(db)

    # Resolve active subscription and plan tier
    sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
    if not sub:
        free_plan = db.query(Plan).filter(Plan.slug == "free").first()
        sub = Subscription(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            plan_id=free_plan.id if free_plan else "free",
            status="active",
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)

    plan = db.query(Plan).filter(Plan.id == sub.plan_id).first()
    tier_slug = plan.slug if plan else "free"
    monthly_limit = plan.monthly_limit if plan else 1000
    rate_limit_rpm = plan.rate_limit_rpm if plan else 60

    # Key generation: 24 random hex bytes (48 hex chars)
    random_hex = secrets.token_hex(24)
    raw_key = f"lon_live_{random_hex}"
    key_prefix = f"lon_live_{random_hex[:8]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    new_key = ApiKey(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        name=payload.name.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        tier=tier_slug,
        monthly_limit=monthly_limit,
        rate_limit_rpm=rate_limit_rpm,
        current_month_usage=0,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_key)
    db.commit()
    db.refresh(new_key)

    return ApiKeyCreateResponse(
        id=new_key.id,
        user_id=new_key.user_id,
        user_email=current_user.email,
        user_name=current_user.name,
        name=new_key.name,
        key_prefix=new_key.key_prefix,
        masked_key=f"{new_key.key_prefix}••••••••••••",
        tier=new_key.tier,
        monthly_limit=new_key.monthly_limit,
        rate_limit_rpm=new_key.rate_limit_rpm,
        current_month_usage=new_key.current_month_usage,
        is_active=new_key.is_active,
        created_at=new_key.created_at,
        last_used_at=new_key.last_used_at,
        secret_key=raw_key,  # Returned ONCE at creation time
    )


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke developer API key")
def revoke_developer_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revokes and deletes an API key owned by the authenticated developer."""
    key = (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.user_id == current_user.id)
        .first()
    )
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or does not belong to your account.",
        )
    db.delete(key)
    db.commit()
    return None
