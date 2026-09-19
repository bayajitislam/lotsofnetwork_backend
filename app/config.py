from typing import List
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Lots of Network API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment & Database
    ENV: str = "development"  # "development" | "staging" | "production" | "test"
    DATABASE_URL: str = "sqlite:///./lotsofnetwork.db"
    
    # Security & JWT Tokens
    SECRET_KEY: str = "super-secret-key-change-in-production-lotsofnetwork-2026"
    REFRESH_SECRET_KEY: str = "super-refresh-secret-key-change-in-production-lotsofnetwork-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # 30-minute short-lived access token
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14     # 14-day refresh token
    
    # Google OAuth 2.0
    GOOGLE_CLIENT_ID: str = ""
    ALLOW_DEV_MOCK_AUTH: bool = False  # Strictly forbidden in production

    # Admin Emails (auto-granted 'admin' role upon verified Google sign-in)
    ADMIN_EMAILS: str = "realbayajitislam@gmail.com,contact@bayajitislam.com"

    # CORS Allowed Origins
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:3001,https://lotsofnetwork.com,https://admin.lotsofnetwork.com"

    @property
    def admin_email_list(self) -> List[str]:
        return [email.strip().lower() for email in self.ADMIN_EMAILS.split(",") if email.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        if self.ENV == "production":
            if self.ALLOW_DEV_MOCK_AUTH:
                raise ValueError("SECURITY VIOLATION: ALLOW_DEV_MOCK_AUTH cannot be enabled in production environment.")
            if not self.GOOGLE_CLIENT_ID or self.GOOGLE_CLIENT_ID.startswith("your-google"):
                raise ValueError("SECURITY VIOLATION: Valid GOOGLE_CLIENT_ID is strictly required in production.")
            if "change-in-production" in self.SECRET_KEY:
                raise ValueError("SECURITY VIOLATION: Production SECRET_KEY must be a cryptographically secure random string.")
        return self

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
