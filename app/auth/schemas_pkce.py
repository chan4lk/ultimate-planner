"""
PKCE (Proof Key for Code Exchange) Pydantic schemas for OAuth 2.1 compliance.
"""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, HttpUrl


class PKCEGenerationRequest(BaseModel):
    """Request to generate PKCE parameters."""
    state: str = Field(..., description="OAuth state parameter")


class PKCEData(BaseModel):
    """PKCE data response."""
    code_verifier: str = Field(..., description="Code verifier for client storage")
    code_challenge: str = Field(..., description="Code challenge for authorization URL")
    code_challenge_method: str = Field(default="S256", description="Code challenge method")
    state: str = Field(..., description="OAuth state parameter")
    expires_at: datetime = Field(..., description="When the PKCE data expires")


class PKCEAuthorizationUrl(BaseModel):
    """Enhanced OAuth authorization URL with PKCE."""
    authorization_url: HttpUrl = Field(..., description="OAuth authorization URL with PKCE parameters")
    state: str = Field(..., description="OAuth state parameter")
    code_verifier: str = Field(..., description="Code verifier to store securely")
    code_challenge: str = Field(..., description="Code challenge included in URL")
    code_challenge_method: str = Field(default="S256", description="Code challenge method")
    expires_at: datetime = Field(..., description="When the PKCE data expires")


class PKCEValidationRequest(BaseModel):
    """Request to validate PKCE code verifier."""
    state: str = Field(..., description="OAuth state parameter")
    code_verifier: str = Field(..., description="Code verifier to validate")


class PKCEValidationResponse(BaseModel):
    """Response from PKCE validation."""
    is_valid: bool = Field(..., description="Whether PKCE validation succeeded")
    state: str = Field(..., description="OAuth state parameter")
    error: Optional[str] = Field(None, description="Validation error message if applicable")


class PKCEStatistics(BaseModel):
    """PKCE service statistics."""
    total_entries: int = Field(..., description="Total PKCE entries in storage")
    active_entries: int = Field(..., description="Active (non-expired) PKCE entries")
    expired_entries: int = Field(..., description="Expired PKCE entries")
    ttl_seconds: int = Field(..., description="TTL in seconds for PKCE data")
    code_challenge_method: str = Field(..., description="Code challenge method used")
    code_verifier_length: int = Field(..., description="Code verifier length")


class EnhancedOAuthUrl(BaseModel):
    """Enhanced OAuth URL response with PKCE support."""
    url: HttpUrl = Field(..., description="OAuth authorization URL")
    state: str = Field(..., description="OAuth state parameter")
    pkce_enabled: bool = Field(default=True, description="Whether PKCE is enabled")
    code_verifier: Optional[str] = Field(None, description="Code verifier (client-side storage)")
    code_challenge: Optional[str] = Field(None, description="Code challenge (for verification)")
    code_challenge_method: Optional[str] = Field(None, description="Code challenge method")


class EnhancedAuthToken(BaseModel):
    """Enhanced auth token with PKCE validation info."""
    access_token: str = Field(..., description="OAuth access token")
    refresh_token: Optional[str] = Field(None, description="OAuth refresh token")
    expires_in: Optional[int] = Field(None, description="Token expiry in seconds")
    token_type: str = Field(default="Bearer", description="Token type")
    scope: Optional[str] = Field(None, description="Token scope")
    pkce_validated: bool = Field(default=False, description="Whether PKCE was validated")


class EnhancedAuthResult(BaseModel):
    """Enhanced authentication result with PKCE validation."""
    success: bool = Field(..., description="Whether authentication succeeded")
    token: Optional[EnhancedAuthToken] = Field(None, description="Authentication token")
    error: Optional[str] = Field(None, description="Error message if applicable")
    user_integration_id: Optional[str] = Field(None, description="User integration ID")
    pkce_validated: bool = Field(default=False, description="Whether PKCE was validated")
    provider: Optional[str] = Field(None, description="OAuth provider name")


class PKCECleanupResult(BaseModel):
    """Result from PKCE cleanup operation."""
    cleaned_count: int = Field(..., description="Number of expired entries cleaned up")
    total_scanned: int = Field(..., description="Total entries scanned")


class PKCESecurityAudit(BaseModel):
    """PKCE security audit information."""
    timestamp: datetime = Field(..., description="Audit timestamp")
    operation: str = Field(..., description="PKCE operation performed")
    state: str = Field(..., description="OAuth state parameter")
    success: bool = Field(..., description="Whether operation succeeded")
    client_ip: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    additional_info: Dict[str, Any] = Field(default_factory=dict, description="Additional audit information")


class PKCEConfiguration(BaseModel):
    """PKCE service configuration."""
    code_verifier_length: int = Field(default=128, description="Code verifier length")
    code_challenge_method: str = Field(default="S256", description="Code challenge method")
    ttl_seconds: int = Field(default=600, description="TTL for PKCE data in seconds")
    redis_prefix: str = Field(default="pkce:state", description="Redis key prefix")
    
    class Config:
        json_encoders = {
            datetime: lambda dt: dt.isoformat()
        }


class PKCEAuthorizationResponse(BaseModel):
    """Response from OAuth authorization URL generation with PKCE."""
    authorization_url: str = Field(..., description="OAuth authorization URL with PKCE parameters")
    state: str = Field(..., description="OAuth state parameter")
    code_challenge: str = Field(..., description="Code challenge for verification")
    provider: str = Field(..., description="OAuth provider name")
    scopes: list[str] = Field(..., description="OAuth scopes")


class PKCECallbackRequest(BaseModel):
    """Request data for OAuth callback with PKCE validation."""
    code: str = Field(..., description="Authorization code from OAuth provider")
    state: str = Field(..., description="OAuth state parameter")
    

class PKCETokenResponse(BaseModel):
    """Token response from PKCE-validated OAuth exchange."""
    access_token: str = Field(..., description="OAuth access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: Optional[int] = Field(None, description="Token expiry in seconds")
    refresh_token: Optional[str] = Field(None, description="OAuth refresh token")
    scope: Optional[str] = Field(None, description="Token scope")
    provider: str = Field(..., description="OAuth provider name")


class PKCEStatsResponse(BaseModel):
    """PKCE statistics response."""
    active_pkce_entries: int = Field(..., description="Active PKCE entries")
    cleanup_batches: int = Field(..., description="Cleanup batch count")
    ttl_seconds: int = Field(..., description="TTL in seconds")
    timestamp: str = Field(..., description="Statistics timestamp")