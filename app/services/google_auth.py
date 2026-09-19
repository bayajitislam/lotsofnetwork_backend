import logging
from typing import Dict, Any
from google.oauth2 import id_token
from google.auth.transport import requests
from fastapi import HTTPException, status
import jwt
from app.config import settings

logger = logging.getLogger(__name__)


def verify_google_id_token(token_str: str) -> Dict[str, Any]:
    """
    Verifies a Google ID token from Google Identity Services.
    Validates:
    - Cryptographic signature against Google's live public JWKS certificates
    - Expiration, issuer (accounts.google.com)
    - audience (if GOOGLE_CLIENT_ID is configured)
    - email_verified is True
    """
    # Test & Development local simulation hook
    if settings.ENV in ("test", "development") and token_str.startswith("eyJhbGciOiJIUzI1Ni"): 
        try:
            decoded = jwt.decode(token_str, options={"verify_signature": False})
            if not decoded.get("email_verified", True):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Google account email is not verified. Access denied."
                )
            return {
                "sub": str(decoded["sub"]),
                "email": str(decoded["email"]),
                "name": decoded.get("name"),
                "picture": decoded.get("picture"),
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )

    try:
        # If GOOGLE_CLIENT_ID is explicitly configured and not placeholder, verify audience
        expected_audience = (
            settings.GOOGLE_CLIENT_ID
            if settings.GOOGLE_CLIENT_ID and not settings.GOOGLE_CLIENT_ID.startswith("your-google")
            else None
        )

        # Verify signature with Google's public JWKS certificates
        id_info = id_token.verify_oauth2_token(
            token_str,
            requests.Request(),
            audience=expected_audience
        )

        if not id_info.get("email_verified"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google account email is not verified. Access denied."
            )

        issuer = id_info.get("iss")
        if issuer not in ("accounts.google.com", "https://accounts.google.com"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token issuer: {issuer}"
            )

        return {
            "sub": str(id_info["sub"]),
            "email": str(id_info["email"]),
            "name": id_info.get("name"),
            "picture": id_info.get("picture"),
        }
    except ValueError as e:
        logger.warning(f"Google token verification failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Google authentication failed: {str(e)}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error verifying Google token")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to authenticate with Google: {str(e)}"
        )
