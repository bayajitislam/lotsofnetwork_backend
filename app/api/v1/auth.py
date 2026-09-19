from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
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
    decode_refresh_token,
)
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/google", response_model=TokenResponse, summary="Sign in or register with Google")
def sign_in_with_google(
    payload: GoogleAuthRequest,
    db: Session = Depends(get_db),
):
    """
    Authenticates a user via Google ID token.
    Automatically assigns role (admin or user) based on dynamic ADMIN_EMAILS check.
    Returns short-lived access token and long-lived refresh token.
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

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenRefreshResponse, summary="Refresh expired access token")
def refresh_access_token(
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    """
    Exchanges a valid refresh token for a fresh short-lived access token.
    Validates token version against the user record for instant revocation.
    """
    decoded = decode_refresh_token(payload.refresh_token)
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

    return TokenRefreshResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )


@router.post("/logout", response_model=LogoutResponse, summary="Revoke all active sessions (Global Logout)")
def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Increments token_version in the database, invalidating all issued access
    and refresh tokens across all devices immediately.
    """
    current_user.token_version += 1
    db.commit()
    return LogoutResponse()


@router.get("/me", response_model=UserResponse, summary="Get current authenticated user profile")
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's profile and active role (admin or user).
    """
    return UserResponse.model_validate(current_user)
