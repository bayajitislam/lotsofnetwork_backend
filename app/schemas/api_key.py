from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ApiKeyResponse(BaseModel):
    id: str
    user_id: str
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    name: str
    key_prefix: str
    masked_key: str
    key_value: Optional[str] = None
    tier: str
    monthly_limit: int
    current_month_usage: int
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ApiKeyCreateRequest(BaseModel):
    user_id: Optional[str] = None
    name: str = Field(default="Production API Key", min_length=2, max_length=128)
    tier: str = Field(default="developer")  # "free" | "developer" | "pro"
    monthly_limit: int = Field(default=10000, ge=100, le=10000000)


class ApiKeyCreateResponse(ApiKeyResponse):
    secret_key: str  # Raw unhashed secret key


class ApiKeyUpdateRequest(BaseModel):
    name: Optional[str] = None
    tier: Optional[str] = None
    monthly_limit: Optional[int] = None
    is_active: Optional[bool] = None
