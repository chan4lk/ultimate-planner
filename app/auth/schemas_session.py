"""Session management schemas."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class SessionInfo(BaseModel):
    """Session information schema."""
    session_id: str
    device_fingerprint: str
    ip_address: str
    user_agent: str
    created_at: str
    last_activity: str
    remember_me: bool = False
    is_current: bool = False


class CreateSessionRequest(BaseModel):
    """Request to create a new session."""
    remember_me: bool = Field(default=False, description="Keep session for extended period")
    device_info: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional device information")


class SessionListResponse(BaseModel):
    """Response with user's active sessions."""
    sessions: List[SessionInfo]
    total_count: int
    max_sessions: int


class InvalidateSessionRequest(BaseModel):
    """Request to invalidate a specific session."""
    session_id: str = Field(..., description="Session ID to invalidate")


class InvalidateAllSessionsResponse(BaseModel):
    """Response for invalidating all sessions."""
    invalidated_count: int
    message: str


class RefreshTokenRequest(BaseModel):
    """Enhanced token refresh request with session validation."""
    refresh_token: Optional[str] = Field(None, description="Optional refresh token")
    session_id: Optional[str] = Field(None, description="Current session ID")


class RefreshTokenResponse(BaseModel):
    """Enhanced token refresh response."""
    access_token: str
    token_type: str = "bearer"
    session_id: str
    expires_in: int


class SessionStatsResponse(BaseModel):
    """Session statistics response."""
    active_sessions: int
    total_sessions_created: int
    blacklisted_tokens: int
    redis_health: Dict[str, Any]


class DeviceInfo(BaseModel):
    """Device information for session creation."""
    device_fingerprint: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_type: Optional[str] = Field(None, description="mobile, desktop, tablet")
    os: Optional[str] = Field(None, description="Operating system")
    browser: Optional[str] = Field(None, description="Browser name")


class EnhancedLoginRequest(BaseModel):
    """Enhanced login request with session management."""
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")
    mfa_token: Optional[str] = Field(None, description="MFA token if required")
    remember_me: bool = Field(default=False, description="Keep session for extended period")
    device_info: Optional[DeviceInfo] = Field(default_factory=DeviceInfo, description="Device information")


class EnhancedLoginResponse(BaseModel):
    """Enhanced login response with session information."""
    access_token: str
    token_type: str = "bearer"
    session_id: str
    expires_in: int
    mfa_required: bool = False
    mfa_verified: bool = False
    user_id: int


class SecurityEvent(BaseModel):
    """Security event schema."""
    event_type: str = Field(..., description="Type of security event")
    user_id: int
    session_id: Optional[str] = None
    ip_address: str
    user_agent: str
    timestamp: datetime
    details: Dict[str, Any] = Field(default_factory=dict)


class SessionSecurityResponse(BaseModel):
    """Session security analysis response."""
    session_id: str
    risk_score: float = Field(..., ge=0, le=1, description="Risk score from 0 (safe) to 1 (high risk)")
    suspicious_activity: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    last_security_check: datetime