import os
import traceback
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import Base, get_engine
from app.models import user, api_key, audit_log, campaign, article, tool_run, crash_log, plan, subscription  # Ensure all models are registered
from app.api.v1 import auth, admin, tools, articles, ads, billing, developer

# Setup uploads directory for ad banner media & article assets
UPLOAD_DIR = settings.uploads_dir
ADS_UPLOAD_DIR = os.path.join(UPLOAD_DIR, "ads")
os.makedirs(ADS_UPLOAD_DIR, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate required secrets before accepting traffic (production/staging only)
    settings.validate_production_secrets()

    # Initialize / update database tables
    # DEV/TEST: create_all is safe for SQLite and initial Supabase setup.
    # PRODUCTION: Run `alembic upgrade head` before starting the server instead.
    #             Set ALEMBIC_ON_STARTUP=true to run it automatically (see config.py).
    Base.metadata.create_all(bind=get_engine())
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Backend API for Lots of Network tools, API monetisation, and Admin Portal.",
    openapi_url=None if settings.is_production else "/openapi.json",
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    lifespan=lifespan,
)

# Static media serving for ad banners & uploads
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API v1 routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(admin.router, prefix=settings.API_V1_STR)
app.include_router(tools.router, prefix=settings.API_V1_STR)
app.include_router(articles.router, prefix=settings.API_V1_STR)
app.include_router(articles.legacy_router, prefix=settings.API_V1_STR)
app.include_router(ads.router, prefix=settings.API_V1_STR)
app.include_router(billing.router, prefix=settings.API_V1_STR)
app.include_router(developer.router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Health"])
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs": None if settings.is_production else "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check():
    """Liveness and database connectivity probe."""
    try:
        from app.database import SessionLocal
        from sqlalchemy import text
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
        finally:
            db.close()
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "database": "disconnected"},
        )
    return {"status": "ok", "database": "connected"}

# ============================================================================
# UNCAUGHT CRASH & EXCEPTION TELEMETRY PIPELINE
# ============================================================================
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    # Pass through standard HTTP client errors (400, 401, 403, 404, 422, etc.)
    if isinstance(exc, StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None),
        )

    error_type = type(exc).__name__
    message = str(exc) or "Internal server error"
    stack_trace = traceback.format_exc()
    service_path = request.url.path
    crash_id = str(uuid.uuid4())

    try:
        from app.database import SessionLocal
        from app.models.crash_log import CrashLog
        db = SessionLocal()
        crash = CrashLog(
            id=crash_id,
            service=service_path,
            error_type=error_type,
            message=message[:500],
            severity="HIGH",
            stack_trace=stack_trace[:5000],  # Capped to 5000 chars to prevent DB bloat
            resolved=False,
        )
        db.add(crash)
        db.commit()
        db.close()
    except Exception as log_err:
        print(f"[CrashLogger Error] Failed to persist crash log: {log_err}")

    # Note: error_type is omitted from public response to prevent class-name leaking
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "error_id": crash_id,
        },
    )
