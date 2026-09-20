import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    GoogleAuthRequest,
    RefreshTokenRequest,
    TokenResponse,
    TokenRefreshResponse,
    LogoutResponse,
    UserResponse,
)
from app.services.google_auth import verify_google_id_token
from app.services.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
)
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


class SetCookiesRequest(BaseModel):
    access_token: str
    refresh_token: str



def _set_auth_cookies(response: Response, access_token: str, refresh_token: Optional[str] = None):
    is_prod = settings.ENV in ("production", "staging")
    samesite = "none" if is_prod else "lax"
    secure = is_prod

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=secure,
        samesite=samesite,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    if refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=secure,
            samesite=samesite,
            max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            path="/",
        )


def _clear_auth_cookies(response: Response):
    is_prod = settings.ENV in ("production", "staging")
    samesite = "none" if is_prod else "lax"
    secure = is_prod

    response.delete_cookie(key="access_token", path="/", secure=secure, samesite=samesite)
    response.delete_cookie(key="refresh_token", path="/", secure=secure, samesite=samesite)


@router.post("/set-cookies", summary="Set auth cookies for cross-subdomain sessions")
def set_auth_cookies(
    payload: SetCookiesRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Explicitly set access and refresh token cookies after cryptographically
    verifying token signatures and confirming the user exists and is active.
    """
    # 1. Verify access token signature and structure
    access_payload = decode_access_token(payload.access_token)
    if not access_payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = access_payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed access token payload.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Verify user in database
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been deactivated.",
        )

    # 3. Check token version revocation
    token_ver = access_payload.get("ver")
    if token_ver is not None and token_ver != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. If refresh token provided, verify its signature and matching user
    if payload.refresh_token:
        refresh_payload = decode_refresh_token(payload.refresh_token)
        if not refresh_payload or refresh_payload.get("sub") != user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or mismatched refresh token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    _set_auth_cookies(response, payload.access_token, payload.refresh_token)
    return {"message": "Auth cookies updated successfully"}


class DeveloperLoginRequest(BaseModel):
    email: str
    name: Optional[str] = "Developer"


@router.post("/developer-login", response_model=TokenResponse, summary="Developer instant login or signup")
def developer_login(
    payload: DeveloperLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Direct developer sign-in or auto-registration for the developer portal.
    DISABLED IN PRODUCTION for security.
    """
    if settings.ENV == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Developer direct login is disabled in production. Please authenticate with Google.",
        )

    email = payload.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid developer email address is required.",
        )

    now = datetime.now(timezone.utc)
    is_admin = email in settings.admin_email_list
    target_role = "admin" if is_admin else "user"

    user = db.query(User).filter(User.email == email).first()
    if user:
        if payload.name:
            user.name = payload.name
        user.last_login_at = now
        db.commit()
        db.refresh(user)
    else:
        user = User(
            email=email,
            name=payload.name or "Developer",
            role=target_role,
            is_active=True,
            token_version=1,
            created_at=now,
            last_login_at=now,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your developer account has been deactivated.",
        )

    token_claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "ver": user.token_version,
    }
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data={"sub": user.id, "ver": user.token_version})

    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.post("/google", response_model=TokenResponse, summary="Sign in or register with Google")
def sign_in_with_google(
    payload: GoogleAuthRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticates a user via Google ID token.
    Automatically assigns role (admin or user) based on dynamic ADMIN_EMAILS check.
    Returns short-lived access token and long-lived refresh token (both in JSON and httpOnly cookies).
    """
    # 1. Verify Google ID token
    google_data = verify_google_id_token(payload.credential)
    email = google_data["email"].lower()
    google_id = google_data["sub"]
    name = google_data.get("name")
    picture = google_data.get("picture")

    # 2. Check if user email qualifies for Admin role
    is_admin = email in settings.admin_email_list
    target_role = "admin" if is_admin else "user"

    # 3. Query existing user by email or google_id
    user = db.query(User).filter((User.email == email) | (User.google_id == google_id)).first()

    now = datetime.now(timezone.utc)

    if user:
        user.name = name or user.name
        user.avatar = picture or user.avatar
        user.google_id = google_id
        user.last_login_at = now
        # Dynamic Role Reconciliation (Supports both elevation and demotion)
        user.role = target_role
        db.commit()
        db.refresh(user)
    else:
        user = User(
            email=email,
            name=name,
            avatar=picture,
            google_id=google_id,
            role=target_role,
            is_active=True,
            token_version=1,
            created_at=now,
            last_login_at=now,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact support.",
        )

    # 4. Generate Access and Refresh Tokens
    token_claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "ver": user.token_version,
    }
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data={"sub": user.id, "ver": user.token_version})

    # Set httpOnly cookies on response
    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenRefreshResponse, summary="Refresh expired access token")
def refresh_access_token(
    request: Request,
    response: Response,
    payload: Optional[RefreshTokenRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Exchanges a valid refresh token for a fresh short-lived access token.
    Validates token version against the user record for instant revocation.
    Accepts refresh token from JSON payload or httpOnly cookie.
    """
    raw_refresh_token = None
    if payload and payload.refresh_token:
        raw_refresh_token = payload.refresh_token
    elif "refresh_token" in request.cookies:
        raw_refresh_token = request.cookies.get("refresh_token")

    if not raw_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token in body or cookie.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    decoded = decode_refresh_token(raw_refresh_token)
    if not decoded:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = decoded.get("sub")
    token_ver = decoded.get("ver")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account has been deactivated.",
        )

    # Validate token version
    if token_ver != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Issue new access token
    new_claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "ver": user.token_version,
    }
    new_access_token = create_access_token(data=new_claims)
    new_refresh_token = create_refresh_token(data={"sub": user.id, "ver": user.token_version})

    _set_auth_cookies(response, new_access_token, new_refresh_token)

    return TokenRefreshResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )


@router.post("/logout", response_model=LogoutResponse, summary="Revoke all active sessions (Global Logout)")
def logout(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Increments token_version in the database, invalidating all issued access
    and refresh tokens across all devices immediately, and clears auth cookies.
    """
    current_user.token_version += 1
    db.commit()
    _clear_auth_cookies(response)
    return LogoutResponse()


@router.get("/me", response_model=UserResponse, summary="Get current authenticated user profile")
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's profile and active role (admin or user).
    """
    return UserResponse.model_validate(current_user)
