from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class PlanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    description: Optional[str] = None
    monthly_limit: int
    rate_limit_rpm: int
    price_cents: int
    stripe_price_id: Optional[str] = None
    is_active: bool


class SubscriptionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    plan: PlanResponse
    plan_slug: Optional[str] = None
    plan_name: Optional[str] = None
    monthly_limit: Optional[int] = None
    rate_limit_rpm: Optional[int] = None
    status: str
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None


class CheckoutSessionRequest(BaseModel):
    plan_slug: str
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None


class CheckoutSessionResponse(BaseModel):
    checkout_url: str
    session_id: str


class CustomerPortalResponse(BaseModel):
    portal_url: str


class VerifySessionRequest(BaseModel):
    session_id: str


class VerifySessionResponse(BaseModel):
    status: str
    message: str
    plan_slug: str
    plan_name: str
