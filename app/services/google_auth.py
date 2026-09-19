from typing import Dict, Any
from google.oauth2 import id_token
from google.auth.transport import requests
from fastapi import HTTPException, status
import jwt
from app.config import settings


def verify_google_id_token(token_str: str) -> Dict[str, Any]:
    """
    Verifies a Google ID token from Google Identity Services.
    Enforces:
    - Cryptographic signature validation via Google public keys (production & staging)
    - audience matching settings.GOOGLE_CLIENT_ID
    - issuer in ('accounts.google.com', 'https://accounts.google.com')
    - email_verified is True (prevents unverified account spoofing)
    """
    is_live_google_config = (
        bool(settings.GOOGLE_CLIENT_ID)
        and not settings.GOOGLE_CLIENT_ID.startswith("your-google")
        and settings.ENV not in ("test", "testing")
    )

    if is_live_google_config:
        try:
            id_info = id_token.verify_oauth2_token(
                token_str,
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            # Security Check: Assert email is verified by Google
            if not id_info.get("email_verified"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Google account email is not verified. Access denied."
                )

            # Security Check: Assert issuer
            issuer = id_info.get("iss")
            if issuer not in ("accounts.google.com", "https://accounts.google.com"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Invalid token issuer: {issuer}"
                )

            return {
                "sub": id_info["sub"],
                "email": id_info["email"],
                "name": id_info.get("name"),
                "picture": id_info.get("picture"),
            }
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Google ID token: {str(e)}"
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to authenticate with Google: {str(e)}"
            )

    # In production, unverified dev mock auth is strictly prohibited
    if settings.ENV == "production":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Production configuration error: GOOGLE_CLIENT_ID is not configured."
        )

    # Development or Testing fallback (strictly requires ALLOW_DEV_MOCK_AUTH or test environment)
    if not (settings.ALLOW_DEV_MOCK_AUTH or settings.ENV in ("test", "testing")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mock authentication is disabled. Please configure GOOGLE_CLIENT_ID or set ALLOW_DEV_MOCK_AUTH=true in .env for development."
        )

    try:
        decoded = jwt.decode(token_str, options={"verify_signature": False})
        email = decoded.get("email")
        sub = decoded.get("sub")
        email_verified = decoded.get("email_verified", True)  # defaults to true for test fixtures

        if not email or not sub:
            raise ValueError("Token must contain 'email' and 'sub' claims.")

        if not email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account email is not verified. Access denied."
            )

        return {
            "sub": str(sub),
            "email": str(email),
            "name": decoded.get("name", "Test User"),
            "picture": decoded.get("picture", None),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token payload: {str(e)}"
        )
