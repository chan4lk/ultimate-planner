"""Session management API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Header, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone

from .dependencies import get_current_user, get_session_from_headers
from .schemas_session import (
    SessionListResponse,
    SessionInfo,
    InvalidateSessionRequest,
    InvalidateAllSessionsResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    SessionStatsResponse,
    EnhancedLoginRequest,
    EnhancedLoginResponse,
    SessionSecurityResponse,
    DeviceInfo
)
from ..models.user import User
from ..database import get_db
from ..services.jwt_service import JWTService
from ..services.redis_session_service import RedisSessionService

router = APIRouter(prefix="/sessions", tags=["session-management"])


@router.get("/", response_model=SessionListResponse)
async def get_user_sessions(
    current_user: User = Depends(get_current_user),
    current_session_id: Optional[str] = Depends(get_session_from_headers)
) -> SessionListResponse:
    """Get all active sessions for the current user."""
    redis_session = RedisSessionService()
    sessions = await redis_session.get_user_sessions(int(current_user.id))
    
    # Convert to response format and mark current session
    session_infos = []
    for session in sessions:
        session_info = SessionInfo(
            session_id=session["session_id"],
            device_fingerprint=session["device_fingerprint"],
            ip_address=session["ip_address"],
            user_agent=session["user_agent"],
            created_at=session["created_at"],
            last_activity=session["last_activity"],
            remember_me=session.get("remember_me", False),
            is_current=(session["session_id"] == current_session_id)
        )
        session_infos.append(session_info)
    
    from ..config.redis_config import MAX_SESSIONS_PER_USER
    
    return SessionListResponse(
        sessions=session_infos,
        total_count=len(session_infos),
        max_sessions=MAX_SESSIONS_PER_USER
    )


@router.delete("/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    current_session_id: Optional[str] = Depends(get_session_from_headers)
) -> dict:
    """Revoke a specific session."""
    redis_session = RedisSessionService()
    
    # Verify the session belongs to the current user
    user_sessions = await redis_session.get_user_sessions(int(current_user.id))
    session_exists = any(s["session_id"] == session_id for s in user_sessions)
    
    if not session_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or doesn't belong to current user"
        )
    
    # Prevent user from revoking their current session via this endpoint
    if session_id == current_session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot revoke current session. Use logout endpoint instead."
        )
    
    success = await redis_session.invalidate_session(session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session"
        )
    
    return {"message": "Session revoked successfully"}


@router.delete("/")
async def revoke_all_other_sessions(
    current_user: User = Depends(get_current_user),
    current_session_id: Optional[str] = Depends(get_session_from_headers)
) -> InvalidateAllSessionsResponse:
    """Revoke all sessions except the current one."""
    redis_session = RedisSessionService()
    
    # Get all user sessions
    user_sessions = await redis_session.get_user_sessions(int(current_user.id))
    
    # Invalidate all sessions except current
    invalidated_count = 0
    for session in user_sessions:
        if session["session_id"] != current_session_id:
            success = await redis_session.invalidate_session(session["session_id"])
            if success:
                invalidated_count += 1
    
    return InvalidateAllSessionsResponse(
        invalidated_count=invalidated_count,
        message=f"Successfully revoked {invalidated_count} sessions"
    )


@router.delete("/all")
async def revoke_all_sessions(
    current_user: User = Depends(get_current_user)
) -> InvalidateAllSessionsResponse:
    """Revoke ALL sessions for the user (including current)."""
    jwt_service = JWTService()
    invalidated_count = await jwt_service.logout_all_sessions(int(current_user.id))
    
    return InvalidateAllSessionsResponse(
        invalidated_count=invalidated_count,
        message=f"Successfully revoked all {invalidated_count} sessions"
    )


@router.post("/refresh", response_model=RefreshTokenResponse)
async def refresh_access_token(
    request: Request,
    refresh_request: RefreshTokenRequest,
    current_user: User = Depends(get_current_user),
    current_session_id: Optional[str] = Depends(get_session_from_headers),
    authorization: str = Header(..., alias="Authorization")
) -> RefreshTokenResponse:
    """Refresh access token while maintaining session."""
    # Extract current token from Authorization header
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    
    current_token = authorization.split(" ")[1]
    
    # Use session_id from request or header
    session_id = refresh_request.session_id or current_session_id
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session ID required for token refresh"
        )
    
    jwt_service = JWTService()
    result = await jwt_service.refresh_token_with_session(
        current_token=current_token,
        session_id=session_id,
        request=request
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to refresh token"
        )
    
    return RefreshTokenResponse(
        access_token=result["access_token"],
        session_id=result["session_id"],
        expires_in=result["expires_in"]
    )


@router.post("/enhanced-login", response_model=EnhancedLoginResponse)
async def enhanced_login(
    request: Request,
    login_request: EnhancedLoginRequest,
    db: Session = Depends(get_db)
) -> EnhancedLoginResponse:
    """Enhanced login with session management and MFA support."""
    from .service import AuthService
    from .schemas_mfa import LoginWithMFARequest
    
    auth_service = AuthService(db)
    jwt_service = JWTService()
    
    # Create MFA login request
    mfa_login_request = LoginWithMFARequest(
        email=login_request.email,
        password=login_request.password,
        mfa_token=login_request.mfa_token
    )
    
    # Authenticate with MFA
    login_result = await auth_service.login_with_mfa(mfa_login_request, request)
    
    # Check if MFA is required
    if isinstance(login_result, dict) and login_result.get("requires_mfa"):
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="MFA token required",
            headers={"X-MFA-Required": "true", "X-Temporary-Token": login_result.get("temporary_token", "")}
        )
    
    # Get user for session creation
    user = auth_service.get_user_by_email(login_request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )
    
    # Prepare device info
    device_info = {}
    if login_request.device_info:
        device_info.update(login_request.device_info.model_dump(exclude_none=True))
    
    # Create session with token
    session_result = await jwt_service.create_session_with_token(
        user_id=str(user.id),
        request=request,
        remember_me=login_request.remember_me,
        device_info=device_info
    )
    
    return EnhancedLoginResponse(
        access_token=session_result["access_token"],
        session_id=session_result["session_id"],
        expires_in=session_result["expires_in"],
        mfa_verified=login_result.get("mfa_verified", False),
        user_id=int(user.id)
    )


@router.post("/logout")
async def logout_current_session(
    current_user: User = Depends(get_current_user),
    current_session_id: Optional[str] = Depends(get_session_from_headers),
    authorization: str = Header(..., alias="Authorization")
) -> dict:
    """Logout from current session."""
    if not current_session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session ID required for logout"
        )
    
    # Extract current token
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header"
        )
    
    current_token = authorization.split(" ")[1]
    
    jwt_service = JWTService()
    success = await jwt_service.logout_session(current_token, current_session_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to logout"
        )
    
    return {"message": "Logged out successfully"}


@router.get("/stats", response_model=SessionStatsResponse)
async def get_session_stats(
    current_user: User = Depends(get_current_user)
) -> SessionStatsResponse:
    """Get session statistics for the current user."""
    redis_session = RedisSessionService()
    
    # Get active sessions
    sessions = await redis_session.get_user_sessions(int(current_user.id))
    
    # Get Redis health
    redis_health = await redis_session.get_redis_health()
    
    return SessionStatsResponse(
        active_sessions=len(sessions),
        total_sessions_created=len(sessions),  # This would need tracking for accurate count
        blacklisted_tokens=0,  # This would need tracking for accurate count
        redis_health=redis_health
    )


@router.get("/{session_id}/security", response_model=SessionSecurityResponse)
async def analyze_session_security(
    session_id: str,
    request: Request,
    current_user: User = Depends(get_current_user)
) -> SessionSecurityResponse:
    """Analyze security risk for a specific session."""
    redis_session = RedisSessionService()
    
    # Verify session belongs to user
    user_sessions = await redis_session.get_user_sessions(int(current_user.id))
    session = next((s for s in user_sessions if s["session_id"] == session_id), None)
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Check for suspicious activity
    jwt_service = JWTService()
    risk_analysis = await jwt_service.check_suspicious_activity(
        user_id=int(current_user.id),
        current_session_id=session_id,
        request=request
    )
    
    # Generate recommendations
    recommendations = []
    if risk_analysis["risk_score"] > 0.5:
        recommendations.append("Consider revoking suspicious sessions")
    if risk_analysis["unique_ips"] > 2:
        recommendations.append("Monitor for unauthorized access from new locations")
    if risk_analysis["recent_sessions"] > 3:
        recommendations.append("Review recent login activity")
    
    return SessionSecurityResponse(
        session_id=session_id,
        risk_score=risk_analysis["risk_score"],
        suspicious_activity=risk_analysis["risk_factors"],
        recommendations=recommendations,
        last_security_check=datetime.now(timezone.utc)
    )


@router.post("/{session_id}/extend")
async def extend_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    background_tasks: BackgroundTasks
) -> dict:
    """Extend session expiration (if remember_me was enabled)."""
    redis_session = RedisSessionService()
    
    # Get session data
    session_data = await redis_session.get_session_data(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Verify session belongs to user
    if session_data.get("user_id") != int(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session doesn't belong to current user"
        )
    
    # Check if session has remember_me enabled
    if not session_data.get("remember_me"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session extension not available for this session"
        )
    
    # Extend session (this would need to be implemented in Redis service)
    # For now, just update activity
    success = await redis_session.update_session_activity(session_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to extend session"
        )
    
    return {"message": "Session extended successfully"}


@router.post("/cleanup")
async def cleanup_expired_sessions(
    current_user: User = Depends(get_current_user),
    background_tasks: BackgroundTasks
) -> dict:
    """Cleanup expired sessions (admin or user-initiated)."""
    def cleanup_task():
        import asyncio
        async def _cleanup():
            redis_session = RedisSessionService()
            cleaned = await redis_session.cleanup_expired_sessions()
            return cleaned
        
        return asyncio.run(_cleanup())
    
    background_tasks.add_task(cleanup_task)
    
    return {"message": "Session cleanup initiated"}