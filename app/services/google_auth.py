from typing import Dict, Any
from google.oauth2 import id_token
from google.auth.transport import requests
from fastapi import HTTPException, status
import jwt
from app.config import settings


def verify_google_id_token(token_str: str) -> Dict[str, Any]:
    """
    Verifies a Google ID token from Google Identity Services.
    Returns email, name, picture, and sub (google_id).
    
    In production with valid GOOGLE_CLIENT_ID: verifies cryptographically against Google's public keys.
    In development/testing: safely decodes claims to enable end-to-end local testing before Google OAuth credentials are created.
    """
    is_live_google_config = (
        settings.GOOGLE_CLIENT_ID 
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
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to authenticate with Google: {str(e)}"
            )

    # Development / Testing fallback
    try:
        decoded = jwt.decode(token_str, options={"verify_signature": False})
        email = decoded.get("email")
        sub = decoded.get("sub")
        if not email or not sub:
            raise ValueError("Token must contain 'email' and 'sub' claims.")
        return {
            "sub": str(sub),
            "email": str(email),
            "name": decoded.get("name", "Test User"),
            "picture": decoded.get("picture", None),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token payload: {str(e)}"
        )
