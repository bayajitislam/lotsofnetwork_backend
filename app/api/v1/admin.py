import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.api_key import ApiKey
from app.models.audit_log import AuditLog
from app.schemas.auth import UserResponse, AuditLogResponse
from app.api.deps import require_admin, get_client_info

router = APIRouter(prefix="/admin", tags=["Admin Portal"])


class AdminStatsResponse(BaseModel):
    total_users: int
    admin_users: int
    standard_users: int
    active_api_keys: int
    audit_logs_count: int
    status: str = "healthy"


class UserStatusUpdateRequest(BaseModel):
    is_active: bool
    reason: Optional[str] = "Admin status update"


@router.get("/stats", response_model=AdminStatsResponse, summary="Get Admin Overview Statistics")
def get_admin_stats(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns platform-wide metrics for admin dashboard. Requires Admin role.
    """
    total_users = db.query(User).count()
    admin_users = db.query(User).filter(User.role == "admin").count()
    standard_users = db.query(User).filter(User.role == "user").count()
    active_api_keys = db.query(ApiKey).filter(ApiKey.is_active == True).count()
    audit_logs_count = db.query(AuditLog).count()

    return AdminStatsResponse(
        total_users=total_users,
        admin_users=admin_users,
        standard_users=standard_users,
        active_api_keys=active_api_keys,
        audit_logs_count=audit_logs_count,
        status="healthy",
    )


@router.get("/users", response_model=List[UserResponse], summary="List all registered users")
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    role: Optional[str] = Query(None, description="Filter by role: admin | user"),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Lists users with pagination and optional role filtering. Requires Admin role.
    """
    query = db.query(User)
    if role:
        query = query.filter(User.role == role)
    users = query.order_by(User.created_at.desc()).offset(skip).limit(limit).all()
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/users/{user_id}/status", response_model=UserResponse, summary="Toggle user active status")
def update_user_status(
    user_id: str,
    payload: UserStatusUpdateRequest,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Enables or disables a user account and records an immutable audit trail.
    Cannot disable own admin account. Requires Admin role.
    """
    if user_id == admin_user.id and not payload.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own administrator account.",
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    old_status = target_user.is_active
    target_user.is_active = payload.is_active
    # If deactivating, revoke all sessions
    if not payload.is_active:
        target_user.token_version += 1

    # Security Audit Trail
    ip, ua = get_client_info(request)
    audit = AuditLog(
        admin_id=admin_user.id,
        admin_email=admin_user.email,
        action="USER_DEACTIVATED" if not payload.is_active else "USER_ACTIVATED",
        resource_type="user",
        resource_id=target_user.id,
        details=json.dumps({
            "target_email": target_user.email,
            "old_status": old_status,
            "new_status": payload.is_active,
            "reason": payload.reason,
        }),
        ip_address=ip,
        user_agent=ua,
    )
    db.add(audit)
    db.commit()
    db.refresh(target_user)

    return UserResponse.model_validate(target_user)


@router.get("/audit-logs", response_model=List[AuditLogResponse], summary="Retrieve Admin Security Audit Logs")
def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Lists administrative audit logs for compliance and security monitoring. Requires Admin role.
    """
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [AuditLogResponse.model_validate(log) for log in logs]
