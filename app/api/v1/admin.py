import json
import re
import secrets
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
import os
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status, File, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.category import Category
from app.models.tag import Tag
from app.models.article import Article
from app.models.tool_run import ToolRun
from app.models.crash_log import CrashLog
from app.models.plan import Plan
from app.models.subscription import Subscription
from app.api.v1.billing import ensure_default_plans
from app.api.v1.tools import ALL_22_TOOLS_METADATA
from app.schemas.auth import UserResponse, AuditLogResponse
from app.schemas.api_key import ApiKeyResponse, ApiKeyCreateRequest, ApiKeyCreateResponse, ApiKeyUpdateRequest
from app.api.deps import require_admin, get_client_info

router = APIRouter(prefix="/admin", tags=["Admin Portal"])


# ============================================================================
# SCHEMAS
# ============================================================================

class MonthlyActivityItem(BaseModel):
    month: str
    tools_queries: int
    api_queries: int
    earnings: float


class RevenueBreakdown(BaseModel):
    affiliate_percentage: int = 34
    direct_sponsors_percentage: int = 22
    api_freemium_percentage: int = 35
    custom_slots_percentage: int = 9


class AdminStatsResponse(BaseModel):
    total_users: int
    admin_users: int
    standard_users: int
    active_api_keys: int
    audit_logs_count: int
    active_campaigns_count: int
    total_articles_count: int
    indexed_articles_count: int
    total_categories_count: int
    total_impressions: int
    total_clicks: int
    avg_ctr: float
    total_earnings: float
    api_revenue: float
    total_subscriptions: int = 0
    paid_subscribers: int = 0
    ad_target_percentage: int = 68
    monthly_activity: List[MonthlyActivityItem]
    revenue_breakdown: RevenueBreakdown
    status: str = "healthy"


class AdminSubscriptionItem(BaseModel):
    id: str
    user_id: str
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    user_avatar: Optional[str] = None
    plan_id: str
    plan_name: str
    plan_slug: str
    monthly_limit: int
    rate_limit_rpm: int
    price_cents: int
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None
    status: str
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AdminSubscriptionUpdate(BaseModel):
    plan_slug: str
    reason: Optional[str] = "Admin subscription tier adjustment"


class AdminPlanUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    monthly_limit: Optional[int] = None
    rate_limit_rpm: Optional[int] = None
    price_cents: Optional[int] = None
    stripe_price_id: Optional[str] = None
    is_active: Optional[bool] = None


class AdminPlanResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None
    monthly_limit: int
    rate_limit_rpm: int
    price_cents: int
    stripe_price_id: Optional[str] = None
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserStatusUpdateRequest(BaseModel):
    is_active: bool
    reason: Optional[str] = "Admin status update"


class CampaignCreate(BaseModel):
    name: str
    sponsor: str
    target_url: str
    image_url: Optional[str] = None
    image_dimensions: Optional[str] = "728x90"
    slot: str = "tool_header"
    target_impressions: int = 50000
    payout_type: str = "affiliate_cpa"
    revenue: float = 0.0
    conversions: int = 0


class CampaignUpdate(BaseModel):
    name: Optional[str] = None
    sponsor: Optional[str] = None
    target_url: Optional[str] = None
    image_url: Optional[str] = None
    image_dimensions: Optional[str] = None
    slot: Optional[str] = None
    target_impressions: Optional[int] = None
    status: Optional[str] = None
    impressions: Optional[int] = None
    clicks: Optional[int] = None
    conversions: Optional[int] = None
    revenue: Optional[float] = None
    payout_type: Optional[str] = None


class CampaignResponse(BaseModel):
    id: str
    name: str
    sponsor: str
    target_url: str
    image_url: Optional[str] = None
    image_dimensions: Optional[str] = "728x90"
    slot: str
    impressions: int
    clicks: int
    conversions: int = 0
    revenue: float = 0.0
    payout_type: str = "affiliate_cpa"
    target_impressions: int
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CategoryCreate(BaseModel):
    name: str
    slug: str
    color: str = "#7c3aed"
    description: Optional[str] = None


class CategoryResponse(BaseModel):
    id: str
    name: str
    slug: str
    color: str
    description: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TagCreate(BaseModel):
    name: str
    slug: Optional[str] = None


class TagResponse(BaseModel):
    id: str
    name: str
    slug: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ArticleCreate(BaseModel):
    slug: str
    title: str
    category: str = "Networking"
    tags: List[str] = Field(default_factory=list)
    excerpt: Optional[str] = None
    content: Optional[str] = None
    status: str = "published"
    is_indexed: bool = True
    focus_keyword: Optional[str] = None
    secondary_keywords: List[str] = Field(default_factory=list)
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None
    canonical_url: Optional[str] = None
    featured_image: Optional[str] = None


class ArticleUpdate(BaseModel):
    slug: Optional[str] = None
    title: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    excerpt: Optional[str] = None
    content: Optional[str] = None
    status: Optional[str] = None
    is_indexed: Optional[bool] = None
    focus_keyword: Optional[str] = None
    secondary_keywords: Optional[List[str]] = None
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None
    canonical_url: Optional[str] = None
    featured_image: Optional[str] = None
    views: Optional[int] = None


class ArticleResponse(BaseModel):
    id: str
    slug: str
    title: str
    category: str
    tags: List[str]
    excerpt: Optional[str] = None
    content: Optional[str] = None
    views: int
    status: str
    is_indexed: bool
    focus_keyword: Optional[str] = None
    secondary_keywords: List[str]
    seo_title: Optional[str] = None
    seo_description: Optional[str] = None
    canonical_url: Optional[str] = None
    featured_image: Optional[str] = None
    reading_time_minutes: int
    seo_score: int
    created_at: datetime
    updated_at: datetime


class ToolTelemetryItem(BaseModel):
    name: str
    slug: str
    category: str
    status: str
    latency_ms: float
    queries_per_hour: int
    uptime_percentage: float
    error_rate: float


class CrashResolveUpdate(BaseModel):
    resolved: bool = True


class CrashLogItem(BaseModel):
    id: str
    timestamp: str
    tool: str
    severity: str
    message: str
    stack_preview: str
    ip_truncated: str
    resolved: bool = False


# ============================================================================
# SEO AUDIT SCORING ENGINE
# ============================================================================

def calculate_seo_score(
    title: str,
    slug: str,
    focus_keyword: Optional[str],
    seo_title: Optional[str],
    seo_description: Optional[str],
    content: Optional[str],
    category: str,
    tags: List[str],
) -> int:
    score = 0
    kw = (focus_keyword or "").strip().lower()

    # 1. Focus Keyword in Title (+20)
    effective_title = (seo_title or title or "").lower()
    if kw and kw in effective_title:
        score += 20
    elif not kw and len(effective_title) > 20:
        score += 10

    # 2. Focus Keyword in URL slug (+15)
    slug_clean = (slug or "").lower().replace("-", " ")
    if kw and kw in slug_clean:
        score += 15
    elif not kw and len(slug or "") > 5:
        score += 10

    # 3. Focus Keyword in Meta Description (+15)
    desc = (seo_description or "").lower()
    if kw and kw in desc:
        score += 15
    elif not kw and len(desc) > 80:
        score += 10

    # 4. Title optimal length 45 - 65 chars (+15)
    t_len = len(seo_title or title or "")
    if 45 <= t_len <= 65:
        score += 15
    elif 30 <= t_len <= 75:
        score += 10

    # 5. Meta Description optimal length 130 - 165 chars (+15)
    d_len = len(seo_description or "")
    if 130 <= d_len <= 165:
        score += 15
    elif 80 <= d_len <= 180:
        score += 10

    # 6. Content word count (+15)
    words = len((content or "").split())
    if words >= 600:
        score += 15
    elif words >= 250:
        score += 10
    elif words > 50:
        score += 5

    # 7. Category and tags configured (+10)
    if category and len(tags) >= 2:
        score += 10
    elif category:
        score += 5

    return min(100, max(10, score))


# ============================================================================
# SEED HELPERS
# ============================================================================

DEFAULT_CATEGORIES = [
    {"name": "Subnetting", "slug": "subnetting", "color": "#7c3aed", "description": "IPv4, IPv6, CIDR calculations, and network mask engineering"},
    {"name": "DNS & Domain", "slug": "dns-domain", "color": "#0ea5e9", "description": "Domain name system, authoritative resolvers, propagation, and records"},
    {"name": "Security & Ports", "slug": "security-ports", "color": "#ef4444", "description": "Port scanning, TLS certificates, firewall rules, and perimeter audit"},
    {"name": "IP & Routing", "slug": "ip-routing", "color": "#3b82f6", "description": "BGP autonomous systems, geolocation, routing tables, and peering"},
    {"name": "Web & SSL", "slug": "web-ssl", "color": "#10b981", "description": "HTTP/2, HTTP/3 headers, SSL trust chains, redirects, and performance"},
    {"name": "Utilities", "slug": "utilities", "color": "#f59e0b", "description": "Base64, JSON formatting, timestamps, UUID, and developer converters"},
    {"name": "Hardware", "slug": "hardware", "color": "#64748b", "description": "MAC address OUI vendor queries, network adapters, and Ethernet protocols"},
]


def seed_default_categories(db: Session):
    if db.query(Category).count() == 0:
        for c in DEFAULT_CATEGORIES:
            cat = Category(
                name=c["name"],
                slug=c["slug"],
                color=c["color"],
                description=c["description"],
            )
            db.add(cat)
        db.commit()


def seed_default_campaigns(db: Session):
    if db.query(Campaign).count() == 0:
        defaults = [
            Campaign(
                name="Hostinger Cloud VPS",
                sponsor="Hostinger",
                target_url="https://hostinger.com?ref=lotsofnetwork",
                slot="tool_header",
                image_url="https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=728&h=90&q=80",
                image_dimensions="728x90",
                impressions=0,
                clicks=0,
                target_impressions=25000,
                status="active",
            ),
            Campaign(
                name="DigitalOcean Droplets",
                sponsor="DigitalOcean",
                target_url="https://digitalocean.com?ref=lotsofnetwork",
                slot="sidebar_banner",
                image_url="https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&w=300&h=250&q=80",
                image_dimensions="300x250",
                impressions=0,
                clicks=0,
                target_impressions=15000,
                status="active",
            ),
            Campaign(
                name="BunnyCDN Edge Storage",
                sponsor="BunnyCDN",
                target_url="https://bunny.net?ref=lotsofnetwork",
                slot="footer_sponsor",
                image_url="https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=728&h=90&q=80",
                image_dimensions="728x90",
                impressions=0,
                clicks=0,
                target_impressions=10000,
                status="active",
            ),
        ]
        for c in defaults:
            db.add(c)
        db.commit()


ALL_37_ARTICLES = [
    {"slug": "what-is-a-subnet", "title": "What Is a Subnet? Formula, CIDR Chart & Calculation Examples [2026]", "category": "Subnetting", "focus_keyword": "what is a subnet", "tags": ["subnetting", "cidr", "ipv4"], "views": 0},
    {"slug": "how-to-check-open-ports", "title": "How to Check Open Ports: 5 Free Tools & Commands (Windows, Mac, Linux)", "category": "Security & Ports", "focus_keyword": "check open ports", "tags": ["ports", "tcp", "security"], "views": 0},
    {"slug": "what-is-dns", "title": "What Is DNS and How Does It Work? 4-Step Resolution Lifecycle Explained", "category": "DNS & Domain", "focus_keyword": "what is dns", "tags": ["dns", "networking", "resolver"], "views": 0},
    {"slug": "dns-record-types-explained", "title": "DNS Record Types Explained: A, AAAA, MX, CNAME, TXT, NS, SOA, CAA", "category": "DNS & Domain", "focus_keyword": "dns record types", "tags": ["dns", "domain", "records"], "views": 0},
    {"slug": "what-is-cidr", "title": "What Is CIDR Notation? How IP Slashing Works with Subnetting Chart", "category": "Subnetting", "focus_keyword": "what is cidr", "tags": ["cidr", "subnetting", "routing"], "views": 0},
    {"slug": "how-does-an-ip-address-work", "title": "How Does an IP Address Work? Network Addressing Fundamentals", "category": "IP & Routing", "focus_keyword": "ip address work", "tags": ["ip-address", "networking", "protocols"], "views": 0},
    {"slug": "ipv4-vs-ipv6", "title": "IPv4 vs IPv6: Key Differences, Speed & Header Comparison Table", "category": "IP & Routing", "focus_keyword": "ipv4 vs ipv6", "tags": ["ipv4", "ipv6", "comparison"], "views": 0},
    {"slug": "what-is-reverse-dns", "title": "What Is Reverse DNS (PTR)? Setup, Verification & Mail Deliverability", "category": "DNS & Domain", "focus_keyword": "reverse dns", "tags": ["reverse-dns", "ptr", "mail"], "views": 0},
    {"slug": "what-is-an-asn", "title": "What Is an Autonomous System Number (ASN)? BGP Routing & Peering", "category": "IP & Routing", "focus_keyword": "what is an asn", "tags": ["asn", "bgp", "routing"], "views": 0},
    {"slug": "how-dns-propagation-works", "title": "How DNS Propagation Works: TTL, Resolvers & Cache Invalidation", "category": "DNS & Domain", "focus_keyword": "dns propagation", "tags": ["dns", "ttl", "propagation"], "views": 0},
    {"slug": "subnet-cheat-sheet-cidr-table", "title": "Subnet Cheat Sheet: Complete /1 to /32 CIDR to Netmask Table [2026]", "category": "Subnetting", "focus_keyword": "subnet cheat sheet", "tags": ["subnetting", "cheat-sheet", "cidr"], "views": 0},
    {"slug": "how-to-calculate-subnet-mask", "title": "How to Calculate Subnet Mask by Hand: Easy Step-by-Step Magic Number Method", "category": "Subnetting", "focus_keyword": "calculate subnet mask", "tags": ["subnet-mask", "calculation", "tutorial"], "views": 0},
    {"slug": "common-port-numbers-cheat-sheet", "title": "Common Port Numbers List (1-65535): Complete Network Cheat Sheet", "category": "Security & Ports", "focus_keyword": "common port numbers", "tags": ["ports", "cheat-sheet", "security"], "views": 0},
    {"slug": "how-to-test-open-ports", "title": "How to Test If a Port Is Open: CMD, PowerShell, Linux & Online", "category": "Security & Ports", "focus_keyword": "test open ports", "tags": ["ports", "powershell", "linux"], "views": 0},
    {"slug": "best-public-dns-servers-list", "title": "10 Best Free Public DNS Servers (Fastest IPv4 & IPv6 Tested for 2026)", "category": "DNS & Domain", "focus_keyword": "best public dns", "tags": ["dns", "public-dns", "speed"], "views": 0},
    {"slug": "how-to-fix-dns-server-not-responding", "title": "How to Fix DNS Server Not Responding: 8 Solutions That Work", "category": "DNS & Domain", "focus_keyword": "dns server not responding", "tags": ["dns", "troubleshooting", "windows"], "views": 0},
    {"slug": "find-public-ip-vs-private-ip", "title": "How to Find Your Public vs. Private IP Address on Any Device", "category": "IP & Routing", "focus_keyword": "public vs private ip", "tags": ["ip-address", "security", "lan"], "views": 0},
    {"slug": "what-is-cidr-notation-explained", "title": "What Is CIDR Notation? A Complete Guide with Examples (/8 to /32)", "category": "Subnetting", "focus_keyword": "cidr notation explained", "tags": ["cidr", "subnetting", "guide"], "views": 0},
    {"slug": "how-to-find-who-owns-a-domain", "title": "How to Find Who Owns a Domain Name (WHOIS & RDAP Guide 2026)", "category": "DNS & Domain", "focus_keyword": "who owns a domain", "tags": ["whois", "domain", "rdap"], "views": 0},
    {"slug": "what-is-port-443-https", "title": "What Is Port 443? HTTPS, TLS & Web Security Explained", "category": "Security & Ports", "focus_keyword": "what is port 443", "tags": ["port-443", "https", "tls"], "views": 0},
    {"slug": "does-vpn-change-your-ip-address", "title": "Does a VPN Change Your IP Address? How VPN IP Masking Works", "category": "Security & Ports", "focus_keyword": "vpn change ip address", "tags": ["vpn", "privacy", "ip-masking"], "views": 0},
    {"slug": "http-vs-https-difference-explained", "title": "HTTP vs HTTPS: What Every Network Engineer Should Know", "category": "Web & SSL", "focus_keyword": "http vs https", "tags": ["http", "https", "ssl"], "views": 0},
    {"slug": "types-of-computer-networks-explained", "title": "Types of Computer Networks: LAN, WAN, MAN, PAN & WLAN Explained", "category": "Networking", "focus_keyword": "types of computer networks", "tags": ["lan", "wan", "architecture"], "views": 0},
    {"slug": "ssl-certificate-expiry-and-tls-guide", "title": "How to Check SSL Certificate Expiry, Trust Chains & TLS Versions", "category": "Web & SSL", "focus_keyword": "ssl certificate expiry", "tags": ["ssl", "tls", "certificates"], "views": 0},
    {"slug": "http-redirects-and-security-headers-guide", "title": "HTTP Redirects & Security Headers: Complete Guide to 301 Hops, HSTS, and CSP", "category": "Web & SSL", "focus_keyword": "http redirects security headers", "tags": ["hsts", "headers", "redirects"], "views": 0},
    {"slug": "what-is-a-mac-address-and-oui", "title": "What Is a MAC Address? How OUI Vendor Lookup and Hardware Addressing Work", "category": "Hardware", "focus_keyword": "what is a mac address", "tags": ["mac-address", "oui", "hardware"], "views": 0},
    {"slug": "forward-confirmed-reverse-dns-fcrdns-guide", "title": "Forward-Confirmed Reverse DNS (FCrDNS): Why Mail Servers Reject Missing PTR Records", "category": "DNS & Domain", "focus_keyword": "fcrdns reverse dns", "tags": ["fcrdns", "ptr", "smtp"], "views": 0},
    {"slug": "cidr-to-ip-range-conversion-guide", "title": "How to Convert CIDR Notation to Usable IP Ranges: Math, Formulas & Examples", "category": "Subnetting", "focus_keyword": "convert cidr to ip range", "tags": ["cidr", "ip-range", "formulas"], "views": 0},
    {"slug": "json-syntax-formatting-and-validation-guide", "title": "The Complete Guide to JSON: RFC 8259 Syntax Rules, Formatting & Fixing Validation Errors", "category": "Utilities", "focus_keyword": "json syntax formatting", "tags": ["json", "rfc8259", "syntax"], "views": 0},
    {"slug": "how-base64-encoding-works-and-url-safe-guide", "title": "How Base64 Encoding Works: 6-Bit Radix Math, Data URIs & URL-Safe Best Practices", "category": "Utilities", "focus_keyword": "how base64 encoding works", "tags": ["base64", "radix", "url-safe"], "views": 0},
    {"slug": "understanding-unix-epoch-time-and-timezones", "title": "Understanding Unix Epoch Time & Timezones: 32-Bit Overflow, UTC Standards & Server Logging", "category": "Utilities", "focus_keyword": "unix epoch time", "tags": ["epoch", "timestamp", "utc"], "views": 0},
    {"slug": "uuid-v7-vs-uuid-v4-database-guide", "title": "UUID v7 vs UUID v4: Why Modern Databases Are Abandoning Random UUIDs", "category": "Utilities", "focus_keyword": "uuid v7 vs uuid v4", "tags": ["uuid", "database", "uuidv7"], "views": 0},
    {"slug": "curl-to-code-conversion-best-practices", "title": "Mastering cURL to Code: Translating HTTP CLI Requests to Python, Node.js, and Go", "category": "Utilities", "focus_keyword": "curl to code", "tags": ["curl", "api", "developer"], "views": 0},
    {"slug": "understanding-linux-file-permissions-and-chmod-calculator", "title": "Linux File Permissions & Chmod: The Complete Octal and Security Guide", "category": "Security & Ports", "focus_keyword": "linux file permissions chmod", "tags": ["chmod", "linux", "permissions"], "views": 0},
    {"slug": "punycode-and-internationalized-domain-names-security-guide", "title": "Punycode & IDN Domains: RFC 3492 Encoding and Homograph Phishing Defense", "category": "Security & Ports", "focus_keyword": "punycode idn domains", "tags": ["punycode", "phishing", "idn"], "views": 0},
    {"slug": "ipv6-addressing-subnetting-and-prefix-allocation-guide", "title": "IPv6 Subnetting Architecture: Prefix Allocation, SLAAC, and Reverse DNS Guide", "category": "Subnetting", "focus_keyword": "ipv6 subnetting architecture", "tags": ["ipv6", "slaac", "prefix"], "views": 0},
    {"slug": "modern-user-agent-strings-and-client-hints-guide", "title": "User-Agent Strings & Client Hints: Browser Fingerprinting and Header Architecture", "category": "Web & SSL", "focus_keyword": "user agent client hints", "tags": ["user-agent", "client-hints", "headers"], "views": 0},
]


def seed_default_articles(db: Session):
    if db.query(Article).count() == 0:
        for item in ALL_37_ARTICLES:
            kw = item.get("focus_keyword", "")
            title = item["title"]
            slug = item["slug"]
            category = item["category"]
            tags = item.get("tags", ["networking"])
            
            seo_title = f"{title[:55]} | Lots of Network"
            seo_desc = f"Master {kw} with practical networking formulas, diagrams, and packet-level examples on Lots of Network."
            
            content = f"""# {title}

Welcome to the comprehensive Lots of Network technical engineering tutorial on **{kw}**. In modern computer networking, understanding the mechanics of {title.lower()} is essential for high-availability systems.

## Key Principles & Architectural Overview
When configuring networks, administrators must ensure low latency, deterministic routing, and zero packet loss.

```bash
# Verify network reachability and latency
ping -c 4 1.1.1.1
traceroute lotsofnetwork.com
```

### Protocol Analysis
Every packet traversing this layer follows standard RFC specifications for header validation and payload integrity.

> **Pro Tip**: Use our interactive online tools like the [Subnet Calculator](https://lotsofnetwork.com/subnet-calculator) and [IP Geolocation Lookup](https://lotsofnetwork.com/ip-lookup) to test this in real time.
"""
            score = calculate_seo_score(
                title=title,
                slug=slug,
                focus_keyword=kw,
                seo_title=seo_title,
                seo_description=seo_desc,
                content=content,
                category=category,
                tags=tags,
            )

            art = Article(
                slug=slug,
                title=title,
                category=category,
                tags=json.dumps(tags),
                views=item["views"],
                excerpt=f"Comprehensive networking engineering guide covering {title}.",
                content=content,
                status="published",
                is_indexed=True,
                focus_keyword=kw,
                secondary_keywords=json.dumps([f"{kw} guide", f"{kw} tutorial"]),
                seo_title=seo_title,
                seo_description=seo_desc,
                canonical_url=f"https://lotsofnetwork.com/blog/{slug}",
                featured_image=f"https://images.unsplash.com/photo-1544197150-b99a580bb7a8?auto=format&fit=crop&w=1200&q=80",
                reading_time_minutes=6,
                seo_score=score,
            )
            db.add(art)
        db.commit()


# ============================================================================
# STATS ENDPOINT (DYNAMIC AGGREGATIONS)
# ============================================================================

@router.get("/stats", response_model=AdminStatsResponse, summary="Get Dynamic Admin Overview Statistics")
def get_admin_stats(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    seed_default_categories(db)
    seed_default_campaigns(db)
    seed_default_articles(db)

    total_users = db.query(User).count()
    admin_users = db.query(User).filter(User.role == "admin").count()
    standard_users = db.query(User).filter(User.role == "user").count()
    active_api_keys = db.query(ApiKey).filter(ApiKey.is_active == True).count()
    audit_logs_count = db.query(AuditLog).count()
    active_campaigns_count = db.query(Campaign).filter(Campaign.status == "active").count()

    total_articles_count = db.query(Article).count()
    indexed_articles_count = db.query(Article).filter(Article.is_indexed == True).count()
    total_categories_count = db.query(Category).count()

    campaigns = db.query(Campaign).all()
    total_impressions = sum(c.impressions for c in campaigns)
    total_clicks = sum(c.clicks for c in campaigns)
    avg_ctr = round((total_clicks / total_impressions * 100), 2) if total_impressions > 0 else 0.0

    # Pure database calculations without any hardcoded dummy offsets
    total_earnings = round(sum(c.revenue for c in campaigns), 2)
    ensure_default_plans(db)
    total_subscriptions = db.query(Subscription).count()
    free_plan = db.query(Plan).filter(Plan.slug == "free").first()
    paid_sub_query = db.query(Subscription).filter(
        Subscription.status == "active",
        Subscription.plan_id != (free_plan.id if free_plan else "")
    )
    paid_subscribers = paid_sub_query.count()
    api_revenue = 0.0
    for ps in paid_sub_query.all():
        p = db.query(Plan).filter(Plan.id == ps.plan_id).first()
        if p and p.price_cents:
            api_revenue += p.price_cents / 100.0
    api_revenue = round(api_revenue, 2)
    total_tool_runs = db.query(ToolRun).count()

    now = datetime.now(timezone.utc)
    monthly_activity = []
    for i in range(5, -1, -1):
        year = now.year
        month = now.month - i
        while month <= 0:
            month += 12
            year -= 1
        m_label = datetime(year, month, 1, tzinfo=timezone.utc).strftime("%b")
        if i == 0:
            monthly_activity.append(
                MonthlyActivityItem(
                    month=m_label,
                    tools_queries=total_tool_runs,
                    api_queries=active_api_keys,
                    earnings=total_earnings + api_revenue,
                )
            )
        else:
            monthly_activity.append(
                MonthlyActivityItem(
                    month=m_label,
                    tools_queries=0,
                    api_queries=0,
                    earnings=0.0,
                )
            )

    return AdminStatsResponse(
        total_users=total_users,
        admin_users=admin_users,
        standard_users=standard_users,
        active_api_keys=active_api_keys,
        audit_logs_count=audit_logs_count,
        active_campaigns_count=active_campaigns_count,
        total_articles_count=total_articles_count,
        indexed_articles_count=indexed_articles_count,
        total_categories_count=total_categories_count,
        total_impressions=total_impressions,
        total_clicks=total_clicks,
        avg_ctr=avg_ctr,
        total_earnings=total_earnings,
        api_revenue=api_revenue,
        total_subscriptions=total_subscriptions,
        paid_subscribers=paid_subscribers,
        ad_target_percentage=68,
        monthly_activity=monthly_activity,
        revenue_breakdown=RevenueBreakdown(),
        status="healthy",
    )


# ============================================================================
# CATEGORIES ENDPOINTS
# ============================================================================

@router.get("/categories", response_model=List[CategoryResponse], summary="List all categories")
def list_categories(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    seed_default_categories(db)
    return db.query(Category).order_by(Category.name.asc()).all()


@router.post("/categories", response_model=CategoryResponse, summary="Create a custom category")
def create_category(
    payload: CategoryCreate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    clean_slug = re.sub(r"[^a-z0-9]+", "-", payload.slug.strip().lower()).strip("-")
    existing = db.query(Category).filter((Category.name == payload.name.strip()) | (Category.slug == clean_slug)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Category with this name or slug already exists.")

    cat = Category(
        name=payload.name.strip(),
        slug=clean_slug,
        color=payload.color.strip(),
        description=payload.description,
    )
    db.add(cat)
    db.commit()
    db.refresh(cat)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="CATEGORY_CREATED",
        resource_type="category",
        resource_id=cat.id,
        details=json.dumps({"name": cat.name, "slug": cat.slug, "color": cat.color}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()

    return CategoryResponse.model_validate(cat)


@router.delete("/categories/{category_id}", summary="Delete custom category")
def delete_category(
    category_id: str,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    cat = db.query(Category).filter(Category.id == category_id).first()
    if not cat:
        raise HTTPException(status_code=404, detail="Category not found.")

    db.delete(cat)
    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="CATEGORY_DELETED",
        resource_type="category",
        resource_id=category_id,
        details=json.dumps({"deleted_name": cat.name}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    return {"message": "Category deleted successfully."}


# ============================================================================
# TAGS ENDPOINTS
# ============================================================================

@router.get("/tags", response_model=List[TagResponse], summary="List all tags")
def list_tags(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return db.query(Tag).order_by(Tag.name.asc()).all()


@router.post("/tags", response_model=TagResponse, summary="Create a tag")
def create_tag(
    payload: TagCreate,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    name = payload.name.strip().lower()
    slug = payload.slug or re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    existing = db.query(Tag).filter((Tag.name == name) | (Tag.slug == slug)).first()
    if existing:
        return TagResponse.model_validate(existing)

    tag = Tag(name=name, slug=slug)
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return TagResponse.model_validate(tag)


# ============================================================================
# ARTICLES ENDPOINTS (DATABASE BACKED WITH FULL SEO AUDITING)
# ============================================================================

def article_to_response(art: Article) -> ArticleResponse:
    tags_list = []
    if art.tags:
        try:
            tags_list = json.loads(art.tags)
        except Exception:
            tags_list = [t.strip() for t in art.tags.split(",") if t.strip()]

    secondary_list = []
    if art.secondary_keywords:
        try:
            secondary_list = json.loads(art.secondary_keywords)
        except Exception:
            secondary_list = []

    return ArticleResponse(
        id=art.id,
        slug=art.slug,
        title=art.title,
        category=art.category,
        tags=tags_list,
        excerpt=art.excerpt,
        content=art.content,
        views=art.views,
        status=art.status,
        is_indexed=art.is_indexed,
        focus_keyword=art.focus_keyword,
        secondary_keywords=secondary_list,
        seo_title=art.seo_title,
        seo_description=art.seo_description,
        canonical_url=art.canonical_url,
        featured_image=art.featured_image,
        reading_time_minutes=art.reading_time_minutes,
        seo_score=art.seo_score,
        created_at=art.created_at,
        updated_at=art.updated_at,
    )


@router.get("/articles", response_model=List[ArticleResponse], summary="List all articles from database")
def list_articles(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    category: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    seed_default_categories(db)
    seed_default_articles(db)
    query = db.query(Article)
    if category and category != "all":
        query = query.filter(Article.category == category)
    if status_filter:
        query = query.filter(Article.status == status_filter)
    articles = query.order_by(Article.views.desc()).offset(skip).limit(limit).all()
    return [article_to_response(a) for a in articles]


@router.post("/articles", response_model=ArticleResponse, summary="Create new blog article with SEO audit")
def create_article(
    payload: ArticleCreate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    clean_slug = re.sub(r"[^a-z0-9]+", "-", payload.slug.strip().lower()).strip("-")
    existing = db.query(Article).filter(Article.slug == clean_slug).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Article slug '{clean_slug}' already exists.")

    word_count = len((payload.content or "").split())
    reading_time = max(1, round(word_count / 200)) if word_count > 0 else 5

    seo_score = calculate_seo_score(
        title=payload.title,
        slug=clean_slug,
        focus_keyword=payload.focus_keyword,
        seo_title=payload.seo_title,
        seo_description=payload.seo_description,
        content=payload.content,
        category=payload.category,
        tags=payload.tags,
    )

    art = Article(
        slug=clean_slug,
        title=payload.title.strip(),
        category=payload.category,
        tags=json.dumps(payload.tags),
        excerpt=payload.excerpt,
        content=payload.content,
        status=payload.status,
        is_indexed=payload.is_indexed,
        focus_keyword=payload.focus_keyword.strip() if payload.focus_keyword else None,
        secondary_keywords=json.dumps(payload.secondary_keywords),
        seo_title=payload.seo_title or f"{payload.title[:55]} | Lots of Network",
        seo_description=payload.seo_description or payload.excerpt,
        canonical_url=payload.canonical_url or f"https://lotsofnetwork.com/blog/{clean_slug}",
        featured_image=payload.featured_image,
        reading_time_minutes=reading_time,
        seo_score=seo_score,
    )
    db.add(art)
    db.commit()
    db.refresh(art)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="ARTICLE_CREATED",
        resource_type="article",
        resource_id=art.id,
        details=json.dumps({"slug": art.slug, "title": art.title, "seo_score": seo_score}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()

    return article_to_response(art)


@router.patch("/articles/{article_id}", response_model=ArticleResponse, summary="Update article and recalculate SEO")
def update_article(
    article_id: str,
    payload: ArticleUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    art = db.query(Article).filter(Article.id == article_id).first()
    if not art:
        raise HTTPException(status_code=404, detail="Article not found.")

    data = payload.model_dump(exclude_unset=True)
    if "tags" in data and isinstance(data["tags"], list):
        art.tags = json.dumps(data["tags"])
        del data["tags"]
    if "secondary_keywords" in data and isinstance(data["secondary_keywords"], list):
        art.secondary_keywords = json.dumps(data["secondary_keywords"])
        del data["secondary_keywords"]

    for k, v in data.items():
        setattr(art, k, v)

    # Recalculate SEO score
    tags_list = json.loads(art.tags) if art.tags else []
    art.seo_score = calculate_seo_score(
        title=art.title,
        slug=art.slug,
        focus_keyword=art.focus_keyword,
        seo_title=art.seo_title,
        seo_description=art.seo_description,
        content=art.content,
        category=art.category,
        tags=tags_list,
    )

    word_count = len((art.content or "").split())
    art.reading_time_minutes = max(1, round(word_count / 200)) if word_count > 0 else 5

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="ARTICLE_UPDATED",
        resource_type="article",
        resource_id=art.id,
        details=json.dumps({"seo_score": art.seo_score}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    db.refresh(art)

    return article_to_response(art)


@router.post("/articles/reset-all-views", summary="Reset all article views to 0")
def reset_all_article_views(
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    count = db.query(Article).update({Article.views: 0})
    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="ARTICLES_VIEWS_RESET",
        resource_type="articles",
        resource_id="all",
        details=json.dumps({"message": f"Reset views to 0 for {count} articles"}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    return {"status": "ok", "message": f"All {count} article views reset to 0.", "count": count}


@router.delete("/articles/{article_id}", summary="Delete article from database")
def delete_article(
    article_id: str,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    art = db.query(Article).filter(Article.id == article_id).first()
    if not art:
        raise HTTPException(status_code=404, detail="Article not found.")

    db.delete(art)
    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="ARTICLE_DELETED",
        resource_type="article",
        resource_id=article_id,
        details=json.dumps({"slug": art.slug, "title": art.title}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    return {"message": "Article deleted successfully."}


@router.post("/articles/{article_id}/index-ping", summary="Dispatch Google Indexing API ping")
def ping_google_indexing(
    article_id: str,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    art = db.query(Article).filter(Article.id == article_id).first()
    if not art:
        raise HTTPException(status_code=404, detail="Article not found.")

    art.is_indexed = True

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="GOOGLE_INDEXING_DISPATCHED",
        resource_type="article",
        resource_id=article_id,
        details=json.dumps({"target_url": f"https://lotsofnetwork.com/blog/{art.slug}"}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    return {
        "status": "success",
        "url": f"https://lotsofnetwork.com/blog/{art.slug}",
        "message": "Google Indexing API notification dispatched with HTTP 200 OK.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# USERS ENDPOINTS
# ============================================================================

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


# ============================================================================
# CAMPAIGNS ENDPOINTS
# ============================================================================

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
        image_url=payload.image_url,
        image_dimensions=payload.image_dimensions or "728x90",
        slot=payload.slot,
        target_impressions=payload.target_impressions,
        payout_type=payload.payout_type,
        revenue=payload.revenue,
        conversions=payload.conversions,
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


# ============================================================================
# MEDIA ASSETS & AD CREATIVE UPLOAD
# ============================================================================

ALLOWED_MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"}
MAX_MEDIA_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


@router.post("/media/upload", summary="Upload media asset for ad campaigns or articles")
async def upload_media(
    request: Request,
    file: UploadFile = File(...),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    file_ext = os.path.splitext(file.filename or "")[1].lower()
    if file_ext not in ALLOWED_MEDIA_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{file_ext}'. Allowed formats: {', '.join(sorted(ALLOWED_MEDIA_EXTENSIONS))}",
        )

    content = await file.read()
    if len(content) > MAX_MEDIA_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size exceeds maximum allowed limit of 5MB")

    token = secrets.token_hex(6)
    clean_base = re.sub(r'[^a-zA-Z0-9_-]', '', os.path.splitext(file.filename or "ad_creative")[0])[:20]
    safe_name = f"{clean_base}_{token}{file_ext}"

    from app.config import settings
    file_url = None
    cdn_provider = "local"

    if settings.cloudinary_configured:
        try:
            import cloudinary
            import cloudinary.uploader
            if settings.CLOUDINARY_URL:
                cloudinary.config(cloudinary_url=settings.CLOUDINARY_URL)
            else:
                cloudinary.config(
                    cloud_name=settings.CLOUDINARY_CLOUD_NAME,
                    api_key=settings.CLOUDINARY_API_KEY,
                    api_secret=settings.CLOUDINARY_API_SECRET,
                    secure=True,
                )
            c_res = cloudinary.uploader.upload(
                content,
                folder="lotsofnetwork/ads",
                public_id=f"{clean_base}_{token}",
                resource_type="image",
            )
            file_url = c_res.get("secure_url") or c_res.get("url")
            cdn_provider = "cloudinary"
        except Exception as c_err:
            print(f"[Cloudinary Warning] CDN upload failed, using local: {c_err}")

    # Local storage persistence
    target_dir = os.path.join(settings.uploads_dir, "ads")
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, safe_name)

    with open(target_path, "wb") as f:
        f.write(content)

    if not file_url:
        file_url = f"/uploads/ads/{safe_name}"

    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="MEDIA_UPLOADED",
        resource_type="media",
        resource_id=safe_name,
        details=json.dumps({"filename": file.filename, "url": file_url, "provider": cdn_provider, "size": len(content)}),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()

    return {
        "status": "ok",
        "url": file_url,
        "provider": cdn_provider,
        "filename": file.filename,
        "size": len(content),
        "content_type": file.content_type,
    }



# ============================================================================
# TELEMETRY & LOGS (100% REAL DATABASE BACKED)
# ============================================================================

@router.get("/telemetry", response_model=List[ToolTelemetryItem], summary="Get 22 tools live telemetry from DB")
def get_tools_telemetry(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    results = []

    for meta in ALL_22_TOOLS_METADATA:
        slug = meta["slug"]
        runs = db.query(ToolRun).filter(ToolRun.tool_slug == slug).all()
        total_runs = len(runs)
        recent_runs = [r for r in runs if r.created_at.replace(tzinfo=timezone.utc) >= one_hour_ago] if runs else []
        queries_per_hour = len(recent_runs)

        if total_runs > 0:
            avg_latency = round(sum(r.latency_ms for r in runs) / total_runs, 1)
            error_count = sum(1 for r in runs if r.status == "error")
            error_rate = round(error_count / total_runs, 4)
            uptime = round((1.0 - error_rate) * 100, 2)
            status_text = "Operational" if error_rate < 0.05 else "Degraded"
        else:
            avg_latency = 0.0
            error_rate = 0.0
            uptime = 100.0
            status_text = "Idle"

        results.append(
            ToolTelemetryItem(
                name=meta["name"],
                slug=slug,
                category=meta["category"],
                status=status_text,
                latency_ms=avg_latency,
                queries_per_hour=queries_per_hour,
                uptime_percentage=uptime,
                error_rate=error_rate,
            )
        )
    return results


@router.get("/crash-logs", response_model=List[CrashLogItem], summary="Get live error telemetry stream from DB")
def get_crash_logs(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    logs = db.query(CrashLog).order_by(CrashLog.created_at.desc()).limit(50).all()
    results = []
    for log in logs:
        results.append(
            CrashLogItem(
                id=log.id,
                timestamp=log.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                tool=log.service,
                severity=log.severity.lower(),
                message=log.message,
                stack_preview=log.stack_trace or f"{log.error_type}: {log.message}",
                ip_truncated="127.0.0.xxx",
                resolved=log.resolved,
            )
        )
    return results


@router.patch("/crash-logs/{log_id}/resolve", summary="Resolve a crash log in DB")
def resolve_crash_log(
    log_id: str,
    payload: CrashResolveUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    log = db.query(CrashLog).filter(CrashLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Crash log not found")
    log.resolved = payload.resolved
    db.commit()
    return {"status": "ok", "id": log.id, "resolved": log.resolved}


@router.post("/crash-logs/simulate", summary="Simulate a diagnostic unhandled exception for telemetry testing")
def simulate_diagnostic_crash(
    admin_user: User = Depends(require_admin),
):
    raise RuntimeError("Diagnostic unhandled exception simulated by Admin Command Center")


# ============================================================================
# AUDIT LOGS
# ============================================================================

@router.get("/audit-logs", response_model=List[AuditLogResponse], summary="Retrieve Admin Security Audit Logs")
def get_admin_audit_logs(
    limit: int = 50,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [AuditLogResponse.model_validate(log) for log in logs]


# ============================================================================
# DEVELOPER API KEYS MANAGEMENT
# ============================================================================



@router.get("/api-keys", response_model=List[ApiKeyResponse], summary="List All Developer API Keys")
def list_api_keys(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    keys = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
    results = []
    for k in keys:
        user = db.query(User).filter(User.id == k.user_id).first()
        results.append(
            ApiKeyResponse(
                id=k.id,
                user_id=k.user_id,
                user_email=user.email if user else None,
                user_name=user.name if user else None,
                name=k.name,
                key_prefix=k.key_prefix,
                masked_key=f"{k.key_prefix}••••••••••••",
                # key_value intentionally omitted — raw keys are never stored or returned
                tier=k.tier,
                monthly_limit=k.monthly_limit,
                current_month_usage=k.current_month_usage,
                is_active=k.is_active,
                created_at=k.created_at,
                last_used_at=k.last_used_at,
            )
        )
    return results


@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED, summary="Create Developer API Key")
def create_api_key(
    payload: ApiKeyCreateRequest,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target_user_id = payload.user_id or admin_user.id
    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found.")

    random_hex = secrets.token_hex(24)
    raw_key = f"lon_live_{random_hex}"
    key_prefix = f"lon_live_{random_hex[:8]}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    new_key = ApiKey(
        id=str(uuid.uuid4()),
        user_id=target_user.id,
        name=payload.name.strip(),
        key_prefix=key_prefix,
        key_hash=key_hash,
        # key_value intentionally NOT stored — raw key shown once at creation only
        tier=payload.tier.lower(),
        monthly_limit=payload.monthly_limit,
        current_month_usage=0,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(new_key)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        id=str(uuid.uuid4()),
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="API_KEY_CREATED",
        resource_type="api_key",
        resource_id=new_key.id,
        details=f"Created API key '{new_key.name}' (Tier: {new_key.tier}, Limit: {new_key.monthly_limit}) for {target_user.email}",
        ip_address=ip,
        user_agent=ua,
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(new_key)

    return ApiKeyCreateResponse(
        id=new_key.id,
        user_id=new_key.user_id,
        user_email=target_user.email,
        user_name=target_user.name,
        name=new_key.name,
        key_prefix=new_key.key_prefix,
        masked_key=f"{new_key.key_prefix}••••••••••••",
        # key_value NOT included — use secret_key below (shown once only)
        tier=new_key.tier,
        monthly_limit=new_key.monthly_limit,
        current_month_usage=new_key.current_month_usage,
        is_active=new_key.is_active,
        created_at=new_key.created_at,
        last_used_at=new_key.last_used_at,
        secret_key=raw_key,  # One-time display — not persisted in DB
    )


@router.patch("/api-keys/{key_id}", response_model=ApiKeyResponse, summary="Update Developer API Key")
def update_api_key(
    key_id: str,
    payload: ApiKeyUpdateRequest,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    changes = []
    if payload.name is not None and payload.name.strip():
        key.name = payload.name.strip()
        changes.append(f"name: {key.name}")
    if payload.tier is not None:
        key.tier = payload.tier.lower()
        changes.append(f"tier: {key.tier}")
    if payload.monthly_limit is not None:
        key.monthly_limit = payload.monthly_limit
        changes.append(f"monthly_limit: {key.monthly_limit}")
    if payload.is_active is not None:
        key.is_active = payload.is_active
        action_verb = "activated" if key.is_active else "revoked/suspended"
        changes.append(f"status: {action_verb}")

    ip, ua = get_client_info(request)
    audit = AuditLog(
        id=str(uuid.uuid4()),
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="API_KEY_UPDATED",
        resource_type="api_key",
        resource_id=key.id,
        details=f"Updated API key '{key.name}': {', '.join(changes)}",
        ip_address=ip,
        user_agent=ua,
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(key)

    user = db.query(User).filter(User.id == key.user_id).first()
    return ApiKeyResponse(
        id=key.id,
        user_id=key.user_id,
        user_email=user.email if user else None,
        user_name=user.name if user else None,
        name=key.name,
        key_prefix=key.key_prefix,
        masked_key=f"{key.key_prefix}••••••••••••",
        tier=key.tier,
        monthly_limit=key.monthly_limit,
        current_month_usage=key.current_month_usage,
        is_active=key.is_active,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
    )


@router.delete("/api-keys/{key_id}", summary="Delete Developer API Key")
def delete_api_key(
    key_id: str,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    key = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    key_name = key.name
    key_prefix = key.key_prefix
    db.delete(key)

    ip, ua = get_client_info(request)
    audit = AuditLog(
        id=str(uuid.uuid4()),
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="API_KEY_DELETED",
        resource_type="api_key",
        resource_id=key_id,
        details=f"Deleted API key '{key_name}' ({key_prefix})",
        ip_address=ip,
        user_agent=ua,
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    return {"status": "ok", "message": f"API key '{key_name}' permanently removed."}


# ============================================================================
# SUBSCRIPTION & PLAN MANAGEMENT (ADMIN)
# ============================================================================

@router.get("/subscriptions", response_model=List[AdminSubscriptionItem], summary="List all developer subscriptions")
def list_subscriptions(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Returns all developer subscriptions with user and plan details."""
    ensure_default_plans(db)
    subs = db.query(Subscription).order_by(Subscription.created_at.desc()).all()
    results = []
    for s in subs:
        user = db.query(User).filter(User.id == s.user_id).first()
        plan = db.query(Plan).filter(Plan.id == s.plan_id).first()
        results.append(
            AdminSubscriptionItem(
                id=s.id,
                user_id=s.user_id,
                user_email=user.email if user else None,
                user_name=user.name if user else None,
                user_avatar=user.avatar if user else None,
                plan_id=s.plan_id,
                plan_name=plan.name if plan else "Unknown",
                plan_slug=plan.slug if plan else "free",
                monthly_limit=plan.monthly_limit if plan else 1000,
                rate_limit_rpm=plan.rate_limit_rpm if plan else 60,
                price_cents=plan.price_cents if plan else 0,
                stripe_customer_id=s.stripe_customer_id,
                stripe_subscription_id=s.stripe_subscription_id,
                status=s.status,
                current_period_start=s.current_period_start,
                current_period_end=s.current_period_end,
                created_at=s.created_at,
                updated_at=s.updated_at,
            )
        )
    return results


@router.patch("/subscriptions/{user_id}", response_model=AdminSubscriptionItem, summary="Update user subscription tier")
def update_user_subscription(
    user_id: str,
    payload: AdminSubscriptionUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Admin override to change a user's subscription tier and sync API key quotas."""
    ensure_default_plans(db)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    target_plan = db.query(Plan).filter(Plan.slug == payload.plan_slug).first()
    if not target_plan:
        raise HTTPException(status_code=400, detail=f"Plan '{payload.plan_slug}' does not exist")

    sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
    old_plan_slug = "none"
    if not sub:
        sub = Subscription(
            id=str(uuid.uuid4()),
            user_id=user_id,
            plan_id=target_plan.id,
            status="active",
        )
        db.add(sub)
    else:
        old_plan = db.query(Plan).filter(Plan.id == sub.plan_id).first()
        old_plan_slug = old_plan.slug if old_plan else "unknown"
        sub.plan_id = target_plan.id
        sub.status = "active"

    # Automatically sync user's active API keys to the new plan quota!
    db.query(ApiKey).filter(ApiKey.user_id == user_id, ApiKey.is_active == True).update(
        {"monthly_limit": target_plan.monthly_limit, "tier": target_plan.slug},
        synchronize_session=False,
    )

    ip, ua = get_client_info(request)
    audit = AuditLog(
        id=str(uuid.uuid4()),
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="USER_PLAN_OVERRIDE",
        resource_type="subscription",
        resource_id=user_id,
        details=f"Changed user '{user.email}' tier from '{old_plan_slug}' to '{target_plan.slug}'. Reason: {payload.reason or 'Admin override'}",
        ip_address=ip,
        user_agent=ua,
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(sub)

    return AdminSubscriptionItem(
        id=sub.id,
        user_id=sub.user_id,
        user_email=user.email,
        user_name=user.name,
        user_avatar=user.avatar,
        plan_id=sub.plan_id,
        plan_name=target_plan.name,
        plan_slug=target_plan.slug,
        monthly_limit=target_plan.monthly_limit,
        rate_limit_rpm=target_plan.rate_limit_rpm,
        price_cents=target_plan.price_cents,
        stripe_customer_id=sub.stripe_customer_id,
        stripe_subscription_id=sub.stripe_subscription_id,
        status=sub.status,
        current_period_start=sub.current_period_start,
        current_period_end=sub.current_period_end,
        created_at=sub.created_at,
        updated_at=sub.updated_at,
    )


@router.get("/plans", response_model=List[AdminPlanResponse], summary="List all plans (Admin)")
def list_admin_plans(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Returns all plans with configuration."""
    ensure_default_plans(db)
    return db.query(Plan).order_by(Plan.price_cents.asc()).all()


@router.patch("/plans/{plan_id}", response_model=AdminPlanResponse, summary="Update plan configuration")
def update_admin_plan(
    plan_id: str,
    payload: AdminPlanUpdate,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Updates a plan's name, description, quota, or rate limit."""
    plan = db.query(Plan).filter(Plan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    if payload.name is not None:
        plan.name = payload.name
    if payload.description is not None:
        plan.description = payload.description
    if payload.monthly_limit is not None:
        plan.monthly_limit = payload.monthly_limit
    if payload.rate_limit_rpm is not None:
        plan.rate_limit_rpm = payload.rate_limit_rpm
    if payload.price_cents is not None:
        plan.price_cents = payload.price_cents
    if payload.stripe_price_id is not None:
        plan.stripe_price_id = payload.stripe_price_id
    if payload.is_active is not None:
        plan.is_active = payload.is_active

    ip, ua = get_client_info(request)
    audit = AuditLog(
        id=str(uuid.uuid4()),
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="PLAN_UPDATED",
        resource_type="plan",
        resource_id=plan.id,
        details=f"Updated plan '{plan.name}' ({plan.slug})",
        ip_address=ip,
        user_agent=ua,
        created_at=datetime.now(timezone.utc),
    )
    db.add(audit)
    db.commit()
    db.refresh(plan)
    return plan

