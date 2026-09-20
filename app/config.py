from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

# ---------------------------------------------------------------------------
# REQUIRED secrets — the server will refuse to start in production/staging
# if any of these are left empty.
# ---------------------------------------------------------------------------
_REQUIRED_IN_PRODUCTION = [
    "SECRET_KEY",
    "REFRESH_SECRET_KEY",
    "DATABASE_URL",
    "GOOGLE_CLIENT_ID",
]


class Settings(BaseSettings):
    PROJECT_NAME: str = "Lots of Network API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Environment: "development" | "production" | "test"
    ENV: str = "production"

    # -----------------------------------------------------------------------
    # Database
    # -----------------------------------------------------------------------
    # Production: postgresql+psycopg2://user:pass@host:5432/dbname
    # Development (Supabase): postgresql://postgres:[PASSWORD]@db.[PROJECT].supabase.co:5432/postgres
    # Fallback (local SQLite — dev/test only):
    DATABASE_URL: str = ""

    def __init__(self, **values):
        super().__init__(**values)

    # -----------------------------------------------------------------------
    # Security & JWT Tokens
    # REQUIRED: Generate with:  python -c "import secrets; print(secrets.token_hex(64))"
    # -----------------------------------------------------------------------
    SECRET_KEY: str = ""
    REFRESH_SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30   # 30-minute short-lived access token
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30     # 30-day persistent sliding session

    # -----------------------------------------------------------------------
    # Google OAuth 2.0
    # REQUIRED: From Google Cloud Console → Credentials → OAuth 2.0 Client ID
    # -----------------------------------------------------------------------
    GOOGLE_CLIENT_ID: str = ""

    # -----------------------------------------------------------------------
    # Admin Access (comma-separated Gmail/Google Workspace emails)
    # These users are auto-granted 'admin' role on first Google sign-in.
    # -----------------------------------------------------------------------
    ADMIN_EMAILS: str = ""

    # -----------------------------------------------------------------------
    # CORS Allowed Origins
    # -----------------------------------------------------------------------
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:3001"

    # -----------------------------------------------------------------------
    # Cloudinary CDN (optional — local file storage used if not configured)
    # NEVER hardcode credentials here. Set CLOUDINARY_URL in your .env file.
    # Format: cloudinary://API_KEY:API_SECRET@CLOUD_NAME
    # -----------------------------------------------------------------------
    CLOUDINARY_CLOUD_NAME: str = ""
    CLOUDINARY_API_KEY: str = ""
    CLOUDINARY_API_SECRET: str = ""
    CLOUDINARY_URL: str = ""

    # -----------------------------------------------------------------------
    # Stripe Billing (required when billing is enabled)
    # -----------------------------------------------------------------------
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""

    # -----------------------------------------------------------------------
    # Feature flags
    # -----------------------------------------------------------------------
    BILLING_ENABLED: bool = False  # Set True when Stripe is configured

    # -----------------------------------------------------------------------
    # Rate limiting (anonymous web users — no API key)
    # -----------------------------------------------------------------------
    ANON_RATE_LIMIT_PER_MINUTE: int = 20  # requests per IP per minute

    # -----------------------------------------------------------------------
    # Computed properties
    # -----------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def admin_email_list(self) -> List[str]:
        return [e.strip().lower() for e in self.ADMIN_EMAILS.split(",") if e.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def uploads_dir(self) -> str:
        from pathlib import Path
        return str(Path(__file__).resolve().parent.parent / "uploads")


    @property
    def cloudinary_configured(self) -> bool:
        return bool(
            self.CLOUDINARY_URL
            or (self.CLOUDINARY_CLOUD_NAME and self.CLOUDINARY_API_KEY and self.CLOUDINARY_API_SECRET)
        )

    def validate_production_secrets(self) -> None:
        """
        Call this at application startup in production/staging.
        Raises ValueError listing every missing required secret so the
        operator knows exactly what to add to their .env before deploying.
        """
        if self.ENV in ("development", "test"):
            return  # Relaxed requirements for local dev

        missing = []
        for key in _REQUIRED_IN_PRODUCTION:
            val = getattr(self, key, "")
            if not val:
                missing.append(key)

        if self.BILLING_ENABLED:
            if not self.STRIPE_SECRET_KEY:
                missing.append("STRIPE_SECRET_KEY (BILLING_ENABLED=True)")
            if not self.STRIPE_WEBHOOK_SECRET:
                missing.append("STRIPE_WEBHOOK_SECRET (BILLING_ENABLED=True)")

        if missing:
            raise ValueError(
                f"[LotsofNetwork] Missing required environment variables for "
                f"ENV={self.ENV!r}. Set these in your .env file before deploying:\n"
                + "\n".join(f"  - {k}" for k in missing)
            )

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
