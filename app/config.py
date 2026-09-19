from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Lots of Network API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Environment & Database
    ENV: str = "production"  # "development" | "production" | "test"
    DATABASE_URL: str = "sqlite:///./lotsofnetwork.db"
    
    # Security & JWT Tokens
    SECRET_KEY: str = "super-secret-key-change-in-production-lotsofnetwork-2026"
    REFRESH_SECRET_KEY: str = "super-refresh-secret-key-change-in-production-lotsofnetwork-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # 30-minute short-lived access token
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14     # 14-day refresh token
    
    # Google OAuth 2.0 Web Client ID
    GOOGLE_CLIENT_ID: str = ""

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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
