from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import GoogleAuthRequest, TokenResponse, UserResponse
from app.services.google_auth import verify_google_id_token
from app.services.security import create_access_token
from app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/google", response_model=TokenResponse, summary="Sign in or register with Google")
def sign_in_with_google(
    payload: GoogleAuthRequest,
    db: Session = Depends(get_db),
):
    """
    Authenticates a user via Google ID token.
    Automatically provisions regular user accounts or admin accounts based on ADMIN_EMAILS whitelist.
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
        # Update user profile information & last login
        user.name = name or user.name
        user.avatar = picture or user.avatar
        user.google_id = google_id
        user.last_login_at = now
        # Elevate to admin if in whitelist and not already admin
        if is_admin and user.role != "admin":
            user.role = "admin"
        db.commit()
        db.refresh(user)
    else:
        # Create new user
        user = User(
            email=email,
            name=name,
            avatar=picture,
            google_id=google_id,
            role=target_role,
            is_active=True,
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

    # 4. Generate JWT access token
    token_claims = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
    }
    access_token = create_access_token(data=token_claims)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse, summary="Get current authenticated user profile")
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the currently authenticated user's profile and active role (admin or user).
    """
    return UserResponse.model_validate(current_user)
