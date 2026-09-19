import os
import traceback
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import Base, engine
from app.models import user, api_key, audit_log, campaign, article, tool_run, crash_log  # Ensure all models are registered
from app.api.v1 import auth, admin, tools, articles, ads

# Setup uploads directory for ad banner media & article assets
UPLOAD_DIR = settings.uploads_dir
ADS_UPLOAD_DIR = os.path.join(UPLOAD_DIR, "ads")
os.makedirs(ADS_UPLOAD_DIR, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize / update database tables
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            cursor = conn.execute(text("PRAGMA table_info(campaigns)"))
            cols = [row[1] for row in cursor.fetchall()]
            if "image_url" not in cols:
                conn.execute(text("ALTER TABLE campaigns ADD COLUMN image_url VARCHAR(1000)"))
            if "image_dimensions" not in cols:
                conn.execute(text("ALTER TABLE campaigns ADD COLUMN image_dimensions VARCHAR(50) DEFAULT '728x90'"))
            conn.commit()
    except Exception as e:
        print(f"[Migration Warning] campaigns column check: {e}")
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Backend API for Lots of Network tools, API monetisation, and Admin Portal.",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
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


@app.get("/", tags=["Health"])
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok"}

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
            stack_trace=stack_trace,
            resolved=False,
        )
        db.add(crash)
        db.commit()
        db.close()
    except Exception as log_err:
        print(f"[CrashLogger Error] Failed to persist crash log: {log_err}")

    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal server error occurred.",
            "error_id": crash_id,
            "error_type": error_type,
        },
    )
