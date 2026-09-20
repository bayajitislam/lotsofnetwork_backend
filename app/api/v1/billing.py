import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.plan import Plan
from app.models.subscription import Subscription
from app.models.api_key import ApiKey
from app.api.deps import get_current_user
from app.schemas.billing import (
    PlanResponse,
    SubscriptionResponse,
    CheckoutSessionRequest,
    CheckoutSessionResponse,
    CustomerPortalResponse,
)

router = APIRouter(prefix="/billing", tags=["Billing & Monetisation"])

DEFAULT_PLANS = [
    {
        "name": "Free Developer",
        "slug": "free",
        "description": "1,000 queries/month for individual developers. No credit card required.",
        "monthly_limit": 1000,
        "rate_limit_rpm": 60,
        "price_cents": 0,
        "stripe_price_id": None,
        "is_active": True,
    },
    {
        "name": "Pro Developer",
        "slug": "pro",
        "description": "50,000 queries/month, higher rate limits, and priority latency.",
        "monthly_limit": 50000,
        "rate_limit_rpm": 300,
        "price_cents": 2900,
        "stripe_price_id": None,
        "is_active": True,
    },
    {
        "name": "Enterprise",
        "slug": "enterprise",
        "description": "500,000 queries/month, custom rate limits, and SLA support.",
        "monthly_limit": 500000,
        "rate_limit_rpm": 1200,
        "price_cents": 19900,
        "stripe_price_id": None,
        "is_active": True,
    },
]


def ensure_default_plans(db: Session):
    """Seed default plans if the plans table is empty."""
    if db.query(Plan).count() == 0:
        for p_data in DEFAULT_PLANS:
            plan = Plan(
                id=str(uuid.uuid4()),
                name=p_data["name"],
                slug=p_data["slug"],
                description=p_data["description"],
                monthly_limit=p_data["monthly_limit"],
                rate_limit_rpm=p_data["rate_limit_rpm"],
                price_cents=p_data["price_cents"],
                stripe_price_id=p_data["stripe_price_id"],
                is_active=p_data["is_active"],
            )
            db.add(plan)
        db.commit()


@router.get("/plans", response_model=List[PlanResponse], summary="List available API plans")
def get_plans(db: Session = Depends(get_db)):
    """Returns all active pricing plans for developers."""
    ensure_default_plans(db)
    return db.query(Plan).filter(Plan.is_active == True).order_by(Plan.price_cents.asc()).all()


@router.get("/subscription", response_model=SubscriptionResponse, summary="Get current user subscription")
def get_user_subscription(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns the authenticated user's current subscription and active plan."""
    ensure_default_plans(db)
    sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
    if not sub:
        free_plan = db.query(Plan).filter(Plan.slug == "free").first()
        sub = Subscription(
            id=str(uuid.uuid4()),
            user_id=current_user.id,
            plan_id=free_plan.id,
            status="active",
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)

    plan = db.query(Plan).filter(Plan.id == sub.plan_id).first()
    plan_resp = PlanResponse.model_validate(plan) if plan else None
    return SubscriptionResponse(
        id=sub.id,
        user_id=sub.user_id,
        plan=plan_resp,
        plan_slug=plan.slug if plan else "free",
        plan_name=plan.name if plan else "Free Developer",
        monthly_limit=plan.monthly_limit if plan else 1000,
        rate_limit_rpm=plan.rate_limit_rpm if plan else 60,
        status=sub.status,
        current_period_start=sub.current_period_start,
        current_period_end=sub.current_period_end,
    )


@router.post("/checkout", response_model=CheckoutSessionResponse, summary="Create Stripe Checkout session")
@router.post("/create-checkout-session", response_model=CheckoutSessionResponse, include_in_schema=False)
def create_checkout_session(
    payload: CheckoutSessionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Initiates a Stripe Checkout session to upgrade API key quota."""
    ensure_default_plans(db)

    # Normalize plan slug
    target_slug = (payload.plan_slug or "").lower().strip()
    if target_slug == "developer":
        target_slug = "pro"

    plan = db.query(Plan).filter(Plan.slug == target_slug, Plan.is_active == True).first()
    if not plan:
        plan = db.query(Plan).filter(Plan.slug == payload.plan_slug, Plan.is_active == True).first()
    if not plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Selected plan '{payload.plan_slug}' not found.")

    # 1. Zero-cost plans (e.g. Free Tier) do not require Stripe checkout
    if plan.price_cents == 0:
        sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
        if not sub:
            sub = Subscription(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                plan_id=plan.id,
                status="active",
            )
            db.add(sub)
        else:
            sub.plan_id = plan.id
            sub.status = "active"

        # Sync user's active API keys to the free plan quota & rate limits
        db.query(ApiKey).filter(ApiKey.user_id == current_user.id, ApiKey.is_active == True).update(
            {"tier": plan.slug, "monthly_limit": plan.monthly_limit, "rate_limit_rpm": plan.rate_limit_rpm},
            synchronize_session=False,
        )
        db.commit()

        return CheckoutSessionResponse(
            checkout_url=payload.success_url or f"/dashboard?upgrade_success={plan.slug}",
            session_id=f"free_sub_{uuid.uuid4().hex[:12]}",
        )

    # 2. Paid plans: attempt Stripe Checkout Session with either stripe_price_id or dynamic price_data
    if settings.BILLING_ENABLED and settings.STRIPE_SECRET_KEY:
        try:
            import stripe
            stripe.api_key = settings.STRIPE_SECRET_KEY

            if plan.stripe_price_id:
                line_item = {"price": plan.stripe_price_id, "quantity": 1}
            else:
                line_item = {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {
                            "name": plan.name,
                            "description": plan.description or f"Lots of Network {plan.name}",
                        },
                        "unit_amount": plan.price_cents,
                        "recurring": {"interval": "month"},
                    },
                    "quantity": 1,
                }

            success_url = payload.success_url or "https://lotsofnetwork.com/dashboard?session_id={CHECKOUT_SESSION_ID}"
            cancel_url = payload.cancel_url or "https://lotsofnetwork.com/dashboard"

            session = stripe.checkout.Session.create(
                payment_method_types=["card"],
                mode="subscription",
                line_items=[line_item],
                customer_email=current_user.email,
                client_reference_id=current_user.id,
                metadata={"user_id": current_user.id, "plan_id": plan.id, "plan_slug": plan.slug},
                success_url=success_url,
                cancel_url=cancel_url,
            )
            return CheckoutSessionResponse(checkout_url=session.url, session_id=session.id)
        except Exception as exc:
            # If in development mode, fallback to instant upgrade so testing is never blocked
            if settings.ENV == "development":
                sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
                if not sub:
                    sub = Subscription(
                        id=str(uuid.uuid4()),
                        user_id=current_user.id,
                        plan_id=plan.id,
                        status="active",
                    )
                    db.add(sub)
                else:
                    sub.plan_id = plan.id
                    sub.status = "active"

                db.query(ApiKey).filter(ApiKey.user_id == current_user.id, ApiKey.is_active == True).update(
                    {"tier": plan.slug, "monthly_limit": plan.monthly_limit, "rate_limit_rpm": plan.rate_limit_rpm},
                    synchronize_session=False,
                )
                db.commit()

                return CheckoutSessionResponse(
                    checkout_url=payload.success_url or f"/dashboard?upgrade_success={plan.slug}",
                    session_id=f"simulated_sub_{uuid.uuid4().hex[:12]}",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Stripe session creation failed: {str(exc)}",
            )

    # 3. If billing is disabled or in development mode without stripe keys
    if settings.ENV == "development":
        sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
        if not sub:
            sub = Subscription(
                id=str(uuid.uuid4()),
                user_id=current_user.id,
                plan_id=plan.id,
                status="active",
            )
            db.add(sub)
        else:
            sub.plan_id = plan.id
            sub.status = "active"

        db.query(ApiKey).filter(ApiKey.user_id == current_user.id, ApiKey.is_active == True).update(
            {"tier": plan.slug, "monthly_limit": plan.monthly_limit, "rate_limit_rpm": plan.rate_limit_rpm},
            synchronize_session=False,
        )
        db.commit()

        return CheckoutSessionResponse(
            checkout_url=payload.success_url or f"/dashboard?upgrade_success={plan.slug}",
            session_id=f"simulated_sub_{uuid.uuid4().hex[:12]}",
        )

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Billing is currently in setup mode. Stripe keys must be configured in production environment.",
    )


@router.post("/portal", response_model=CustomerPortalResponse, summary="Create Stripe Customer Portal session")
@router.post("/customer-portal", response_model=CustomerPortalResponse, include_in_schema=False)
def create_customer_portal(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generates a billing portal link for users to update or cancel their subscription."""
    if not settings.BILLING_ENABLED or not settings.STRIPE_SECRET_KEY:
        if settings.ENV in ("development", "test"):
            return CustomerPortalResponse(portal_url="/dashboard?portal=development_mode")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Billing is currently in setup mode.",
        )

    try:
        import stripe
        stripe.api_key = settings.STRIPE_SECRET_KEY
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stripe SDK is not installed on the server.",
        )

    sub = db.query(Subscription).filter(Subscription.user_id == current_user.id).first()
    if not sub or not sub.stripe_customer_id:
        if settings.ENV in ("development", "test"):
            return CustomerPortalResponse(portal_url="/dashboard?portal=development_mode")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Stripe customer found for this account.",
        )

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=sub.stripe_customer_id,
            return_url="https://lotsofnetwork.com/developer",
        )
        return CustomerPortalResponse(portal_url=portal_session.url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate portal session: {str(exc)}",
        )


@router.post("/webhook", summary="Stripe Webhook Receiver")
async def stripe_webhook(
    request: Request,
    stripe_signature: Optional[str] = Header(None, alias="stripe-signature"),
    db: Session = Depends(get_db),
):
    """
    Receives and processes Stripe webhooks:
    - checkout.session.completed: upgrades user subscription and sets ApiKey monthly limit
    - customer.subscription.deleted: downgrades user back to Free tier
    """
    try:
        import stripe
        stripe.api_key = settings.STRIPE_SECRET_KEY
    except ImportError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Stripe SDK missing")

    body = await request.body()

    event = None
    if settings.STRIPE_WEBHOOK_SECRET and stripe_signature:
        try:
            event = stripe.Webhook.construct_event(body, stripe_signature, settings.STRIPE_WEBHOOK_SECRET)
        except Exception as err:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid webhook signature: {err}")
    else:
        import json
        try:
            event = json.loads(body)
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON body")

    event_type = event.get("type")
    data_obj = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        user_id = data_obj.get("client_reference_id") or data_obj.get("metadata", {}).get("user_id")
        plan_id = data_obj.get("metadata", {}).get("plan_id")
        customer_id = data_obj.get("customer")
        subscription_id = data_obj.get("subscription")

        if user_id and plan_id:
            plan = db.query(Plan).filter(Plan.id == plan_id).first()
            sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()

            # Idempotency: skip if this stripe_subscription_id is already recorded
            if subscription_id and sub and sub.stripe_subscription_id == subscription_id:
                return {"status": "already_processed", "event": event_type}

            if not sub:
                sub = Subscription(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    plan_id=plan_id,
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=subscription_id,
                    status="active",
                )
                db.add(sub)
            else:
                sub.plan_id = plan_id
                sub.stripe_customer_id = customer_id
                sub.stripe_subscription_id = subscription_id
                sub.status = "active"

            # Sync active API keys to the new plan quota and RPM!
            if plan:
                db.query(ApiKey).filter(ApiKey.user_id == user_id, ApiKey.is_active == True).update(
                    {"monthly_limit": plan.monthly_limit, "rate_limit_rpm": plan.rate_limit_rpm},
                    synchronize_session=False,
                )
            db.commit()

    elif event_type in ("customer.subscription.deleted", "customer.subscription.updated"):
        customer_id = data_obj.get("customer")
        sub_id = data_obj.get("id")
        sub_status = data_obj.get("status")
        if event_type == "customer.subscription.deleted":
            sub_status = "canceled"

        from sqlalchemy import or_
        clauses = []
        if customer_id:
            clauses.append(Subscription.stripe_customer_id == customer_id)
        if sub_id:
            clauses.append(Subscription.stripe_subscription_id == sub_id)

        sub = db.query(Subscription).filter(or_(*clauses)).first() if clauses else None

        if sub:
            sub.status = sub_status or "canceled"
            if sub_status in ("canceled", "unpaid") or event_type == "customer.subscription.deleted":
                ensure_default_plans(db)
                free_plan = db.query(Plan).filter(Plan.slug == "free").first()
                if free_plan:
                    sub.plan_id = free_plan.id
                    db.query(ApiKey).filter(ApiKey.user_id == sub.user_id, ApiKey.is_active == True).update(
                        {"monthly_limit": free_plan.monthly_limit, "rate_limit_rpm": free_plan.rate_limit_rpm},
                        synchronize_session=False,
                    )
            db.commit()

    return {"status": "success", "event": event_type}
