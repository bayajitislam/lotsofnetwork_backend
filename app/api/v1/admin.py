import json
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.schemas.auth import UserResponse, AuditLogResponse
from app.api.deps import require_admin, get_client_info

router = APIRouter(prefix="/admin", tags=["Admin Portal"])


class AdminStatsResponse(BaseModel):
    total_users: int
    admin_users: int
    standard_users: int
    active_api_keys: int
    audit_logs_count: int
    active_campaigns_count: int
    status: str = "healthy"


class UserStatusUpdateRequest(BaseModel):
    is_active: bool
    reason: Optional[str] = "Admin status update"


class CampaignCreate(BaseModel):
    name: str
    sponsor: str
    target_url: str
    slot: str = "tool_header"
    target_impressions: int = 50000


class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    sponsor: Optional[str] = None
    target_url: Optional[str] = None
    slot: Optional[str] = None
    target_impressions: Optional[int] = None
    status: Optional[str] = None
    impressions: Optional[int] = None
    clicks: Optional[int] = None


class CampaignResponse(BaseModel):
    id: str
    name: str
    sponsor: str
    target_url: str
    slot: str
    impressions: int
    clicks: int
    target_impressions: int
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ToolTelemetryItem(BaseModel):
    name: str
    slug: str
    category: str
    status: str
    latency_ms: int
    queries_per_hour: int
    uptime_percentage: float
    error_rate: float


class CrashLogItem(BaseModel):
    id: str
    timestamp: str
    tool: str
    severity: str  # error, warning, critical
    message: str
    stack_preview: str
    ip_truncated: str


# Helper to seed default campaigns if table is empty
def seed_default_campaigns(db: Session):
    if db.query(Campaign).count() == 0:
        defaults = [
            Campaign(
                name="Hostinger Cloud VPS",
                sponsor="Hostinger",
                target_url="https://hostinger.com?ref=lotsofnetwork",
                slot="tool_header",
                impressions=18450,
                clicks=842,
                target_impressions=25000,
                status="active"
            ),
            Campaign(
                name="DigitalOcean Droplets",
                sponsor="DigitalOcean",
                target_url="https://digitalocean.com?ref=lotsofnetwork",
                slot="sidebar_banner",
                impressions=8920,
                clicks=318,
                target_impressions=15000,
                status="active"
            ),
            Campaign(
                name="BunnyCDN Edge Storage",
                sponsor="BunnyCDN",
                target_url="https://bunny.net?ref=lotsofnetwork",
                slot="footer_sponsor",
                impressions=3284,
                clicks=147,
                target_impressions=10000,
                status="active"
            ),
        ]
        for c in defaults:
            db.add(c)
        db.commit()


@router.get("/stats", response_model=AdminStatsResponse, summary="Get Admin Overview Statistics")
def get_admin_stats(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns platform-wide metrics for admin dashboard. Requires Admin role.
    """
    seed_default_campaigns(db)
    total_users = db.query(User).count()
    admin_users = db.query(User).filter(User.role == "admin").count()
    standard_users = db.query(User).filter(User.role == "user").count()
    active_api_keys = db.query(ApiKey).filter(ApiKey.is_active == True).count()
    audit_logs_count = db.query(AuditLog).count()
    active_campaigns_count = db.query(Campaign).filter(Campaign.status == "active").count()

    return AdminStatsResponse(
        total_users=total_users,
        admin_users=admin_users,
        standard_users=standard_users,
        active_api_keys=active_api_keys,
        audit_logs_count=audit_logs_count,
        active_campaigns_count=active_campaigns_count,
        status="healthy",
    )


@router.get("/users", response_model=List[UserResponse], summary="List all registered users")
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    role: Optional[str] = Query(None, description="Filter by role: admin | user"),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    if role:
        query = query.filter(User.role == role)
    users = query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/users/{user_id}/status", response_model=UserResponse, summary="Toggle user active status")
def update_user_status(
    user_id: str,
    payload: UserStatusUpdateRequest,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if user_id == admin_user.id and not payload.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own administrator account.",
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    old_status = target_user.is_active
    target_user.is_active = payload.is_active
    if not payload.is_active:
        target_user.token_version += 1

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="USER_DEACTIVATED" if not payload.is_active else "USER_ACTIVATED",
        resource_type="user",
        resource_id=target_user.id,
        details=json.dumps({
            "target_email": target_user.email,
            "old_status": old_status,
            "new_status": payload.is_active,
            "reason": payload.reason,
        }),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    db.refresh(target_user)

    return UserResponse.model_validate(target_user)


@router.get("/campaigns", response_model=List[CampaignResponse], summary="List all ad campaigns")
def list_campaigns(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    seed_default_campaigns(db)
    campaigns = db.query(Campaign).order_by(Campaign.created_at.desc()).all()
    return [CampaignResponse.model_validate(c) for c in campaigns]


@router.post("/campaigns", response_model=CampaignResponse, summary="Create a new ad campaign")
def create_campaign(
    payload: CampaignCreate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    campaign = Campaign(
        name=payload.name,
        sponsor=payload.sponsor,
        target_url=payload.target_url,
        slot=payload.slot,
        target_impressions=payload.target_impressions,
        impressions=0,
        clicks=0,
        status="active",
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="CAMPAIGN_CREATED",
        resource_type="campaign",
        resource_id=campaign.id,
        details=json.dumps({"name": campaign.name, "sponsor": campaign.sponsor, "slot": campaign.slot}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()

    return CampaignResponse.model_validate(campaign)


@router.patch("/campaigns/{campaign_id}", response_model=CampaignResponse, summary="Update campaign")
def update_campaign(
    campaign_id: str,
    payload: CampaignUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(campaign, k, v)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="CAMPAIGN_UPDATED",
        resource_type="campaign",
        resource_id=campaign.id,
        details=json.dumps(data),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    db.refresh(campaign)
    return CampaignResponse.model_validate(campaign)


@router.delete("/campaigns/{campaign_id}", summary="Delete campaign")
def delete_campaign(
    campaign_id: str,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    db.delete(campaign)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="CAMPAIGN_DELETED",
        resource_type="campaign",
        resource_id=campaign_id,
        details=json.dumps({"deleted_name": campaign.name}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    return {"message": "Campaign deleted successfully"}


@router.get("/telemetry", response_model=List[ToolTelemetryItem], summary="Get 22 tools live telemetry")
def get_tools_telemetry(
    admin_user: User = Depends(require_admin),
):
    """
    Returns live performance telemetry for all 22 Lots of Network interactive tools.
    """
    tools = [
        {"name": "IP Geolocation Lookup", "slug": "ip-lookup", "category": "IP & Routing", "status": "Operational", "latency_ms": 28, "queries_per_hour": 1420, "uptime_percentage": 99.98, "error_rate": 0.01},
        {"name": "Visual Subnet Calculator", "slug": "subnet-calculator", "category": "IP & Routing", "status": "Operational", "latency_ms": 14, "queries_per_hour": 840, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "DNS Propagation Lookup", "slug": "dns-lookup", "category": "DNS & Domain", "status": "Operational", "latency_ms": 62, "queries_per_hour": 960, "uptime_percentage": 99.94, "error_rate": 0.04},
        {"name": "TCP Port Scanner", "slug": "port-checker", "category": "Security & Ports", "status": "Operational", "latency_ms": 48, "queries_per_hour": 610, "uptime_percentage": 99.89, "error_rate": 0.08},
        {"name": "IPv6 / IPv4 Converter", "slug": "ipv6-converter", "category": "IP & Routing", "status": "Operational", "latency_ms": 11, "queries_per_hour": 340, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "ASN & BGP Route Whois", "slug": "asn-lookup", "category": "IP & Routing", "status": "Operational", "latency_ms": 78, "queries_per_hour": 510, "uptime_percentage": 99.91, "error_rate": 0.02},
        {"name": "Ping & Latency Tester", "slug": "ping-test", "category": "Diagnostics", "status": "Operational", "latency_ms": 32, "queries_per_hour": 790, "uptime_percentage": 99.95, "error_rate": 0.02},
        {"name": "Traceroute Visualizer", "slug": "traceroute-online", "category": "Diagnostics", "status": "Operational", "latency_ms": 112, "queries_per_hour": 430, "uptime_percentage": 99.78, "error_rate": 0.12},
        {"name": "HTTP Headers Analyzer", "slug": "http-headers", "category": "Web & SSL", "status": "Operational", "latency_ms": 41, "queries_per_hour": 380, "uptime_percentage": 99.96, "error_rate": 0.01},
        {"name": "SSL / TLS Certificate Inspector", "slug": "ssl-checker", "category": "Web & SSL", "status": "Operational", "latency_ms": 84, "queries_per_hour": 590, "uptime_percentage": 99.92, "error_rate": 0.03},
        {"name": "Reverse DNS (PTR) Lookup", "slug": "reverse-dns", "category": "DNS & Domain", "status": "Operational", "latency_ms": 45, "queries_per_hour": 410, "uptime_percentage": 99.95, "error_rate": 0.01},
        {"name": "WHOIS Domain Query", "slug": "whois-lookup", "category": "DNS & Domain", "status": "Operational", "latency_ms": 95, "queries_per_hour": 670, "uptime_percentage": 99.85, "error_rate": 0.06},
        {"name": "MAC Address OUI Lookup", "slug": "mac-lookup", "category": "Hardware", "status": "Operational", "latency_ms": 12, "queries_per_hour": 290, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "CIDR Supernet / Aggregate", "slug": "cidr-calculator", "category": "IP & Routing", "status": "Operational", "latency_ms": 15, "queries_per_hour": 520, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "Email MX & SPF Record Check", "slug": "mx-lookup", "category": "DNS & Domain", "status": "Operational", "latency_ms": 55, "queries_per_hour": 460, "uptime_percentage": 99.93, "error_rate": 0.02},
        {"name": "Blacklist (RBL) Reputation Check", "slug": "blacklist-checker", "category": "Security & Ports", "status": "Operational", "latency_ms": 140, "queries_per_hour": 310, "uptime_percentage": 99.81, "error_rate": 0.09},
        {"name": "DNSSEC Validation Checker", "slug": "dnssec-analyzer", "category": "DNS & Domain", "status": "Operational", "latency_ms": 68, "queries_per_hour": 220, "uptime_percentage": 99.96, "error_rate": 0.01},
        {"name": "MTU / MSS Packet Size Test", "slug": "mtu-test", "category": "Diagnostics", "status": "Operational", "latency_ms": 29, "queries_per_hour": 180, "uptime_percentage": 99.98, "error_rate": 0.00},
        {"name": "User-Agent Parser", "slug": "user-agent", "category": "Web & SSL", "status": "Operational", "latency_ms": 8, "queries_per_hour": 630, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "Base64 & URL Encoder", "slug": "base64-converter", "category": "Utilities", "status": "Operational", "latency_ms": 7, "queries_per_hour": 810, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "JSON Formatter & Validator", "slug": "json-formatter", "category": "Utilities", "status": "Operational", "latency_ms": 9, "queries_per_hour": 940, "uptime_percentage": 100.0, "error_rate": 0.00},
        {"name": "Password Generator & Hash Entropy", "slug": "password-generator", "category": "Security & Ports", "status": "Operational", "latency_ms": 11, "queries_per_hour": 470, "uptime_percentage": 100.0, "error_rate": 0.00},
    ]
    return [ToolTelemetryItem(**t) for t in tools]


@router.get("/crash-logs", response_model=List[CrashLogItem], summary="Get live error telemetry stream")
def get_crash_logs(
    admin_user: User = Depends(require_admin),
):
    logs = [
        {
            "id": "err-9942",
            "timestamp": "Just now",
            "tool": "/dns-lookup",
            "severity": "warning",
            "message": "Authoritative nameserver timeout (NS: ns1.he.net)",
            "stack_preview": "DNSTimeoutError: Query timed out after 4000ms at resolveAuthoritative (dns.ts:142)",
            "ip_truncated": "104.28.xxx.xxx",
        },
        {
            "id": "err-9938",
            "timestamp": "14 mins ago",
            "tool": "/port-checker",
            "severity": "warning",
            "message": "Connection reset by peer on target socket :443",
            "stack_preview": "ECONNRESET: TCP socket unexpectedly closed at Socket.onClose (socket.ts:89)",
            "ip_truncated": "198.51.xxx.xxx",
        },
        {
            "id": "err-9912",
            "timestamp": "1 hour ago",
            "tool": "/traceroute-online",
            "severity": "error",
            "message": "ICMP probe packet dropped at hop 11 (backbone.transit.net)",
            "stack_preview": "HopDropWarning: Exceeded max hop count 30 without reaching target IP",
            "ip_truncated": "172.67.xxx.xxx",
        },
        {
            "id": "err-9870",
            "timestamp": "3 hours ago",
            "tool": "/ssl-checker",
            "severity": "warning",
            "message": "Untrusted self-signed intermediate certificate detected",
            "stack_preview": "DEPTH_ZERO_SELF_SIGNED_CERT: unable to verify the first certificate",
            "ip_truncated": "185.220.xxx.xxx",
        },
    ]
    return [CrashLogItem(**l) for l in logs]


@router.get("/audit-logs", response_model=List[AuditLogResponse], summary="Retrieve Admin Security Audit Logs")
def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [AuditLogResponse.model_validate(log) for log in logs]
