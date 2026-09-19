from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr


class GoogleAuthRequest(BaseModel):
    credential: str  # Google ID token (JWT)


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    name: Optional[str] = None
    avatar: Optional[str] = None
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class TokenPayload(BaseModel):
    sub: str
    email: str
    role: str
    exp: int
