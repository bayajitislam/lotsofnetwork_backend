from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.services.security import decode_access_token

security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    token: Optional[str] = None
    if credentials:
        token = credentials.credentials
    elif "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Missing Bearer token or session cookie.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    token_ver = payload.get("ver")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated.",
        )

    # Security Check: Verify token version matches user.token_version (Global revocation)
    if token_ver is not None and token_ver != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency verifying any authenticated active user."""
    return current_user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency strictly verifying the user has the 'admin' role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required.",
        )
    return current_user


import ipaddress

_LOOPBACK_OR_TEST = {"127.0.0.1", "::1", "localhost", "testclient"}


def _is_trusted_proxy(ip: str) -> bool:
    """Check if the direct peer is a loopback or private network proxy."""
    if not ip or ip == "unknown":
        return False
    if ip in _LOOPBACK_OR_TEST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """
    Extracts the genuine client IP address with anti-spoofing protection.
    Only honors proxy headers (CF-Connecting-IP, X-Real-IP, X-Forwarded-For)
    if the direct connection originates from a trusted local/private reverse proxy.
    """
    peer_ip = request.client.host if request.client else "unknown"

    if _is_trusted_proxy(peer_ip):
        # 1. Cloudflare header (highest priority when behind Cloudflare)
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()

        # 2. NGINX / reverse proxy single real IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        # 3. Standard X-Forwarded-For header
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_candidate = forwarded.split(",")[0].strip()
            if client_candidate:
                return client_candidate

    return peer_ip


def get_client_info(request: Request) -> tuple[str, str]:
    """Helper to extract client IP and user agent for audit logging."""
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "unknown")[:500]
    return ip, ua
