"""MFA (Multi-Factor Authentication) Pydantic schemas."""
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime
import re


class MFASetupRequest(BaseModel):
    """Request to setup MFA for user."""
    pass


class MFASetupResponse(BaseModel):
    """Response after MFA setup initiation."""
    secret_key: str = Field(..., description="Base32 encoded secret key for TOTP")
    qr_code_url: str = Field(..., description="URL for QR code generation")
    backup_codes: List[str] = Field(..., description="List of backup codes")
    
    class Config:
        json_schema_extra = {
            "example": {
                "secret_key": "JBSWY3DPEHPK3PXP",
                "qr_code_url": "/auth/mfa/qr-code",
                "backup_codes": ["123456789", "987654321"]
            }
        }


class MFAVerifyRequest(BaseModel):
    """Request to verify TOTP token."""
    token: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP token")
    
    @field_validator('token')
    @classmethod
    def validate_token(cls, v):
        """Validate token format."""
        if not v.isdigit():
            raise ValueError('Token must contain only digits')
        return v


class MFAEnableRequest(BaseModel):
    """Request to enable MFA after verification."""
    token: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP token for confirmation")
    
    @field_validator('token')
    @classmethod
    def validate_token(cls, v):
        """Validate token format."""
        if not v.isdigit():
            raise ValueError('Token must contain only digits')
        return v


class MFADisableRequest(BaseModel):
    """Request to disable MFA."""
    password: str = Field(..., description="Current password for security confirmation")
    token: Optional[str] = Field(None, min_length=6, max_length=6, description="6-digit TOTP token or backup code")
    
    @field_validator('token')
    @classmethod
    def validate_token(cls, v):
        """Validate token format if provided."""
        if v and not (v.isdigit() and len(v) >= 6):
            raise ValueError('Token must be at least 6 digits')
        return v


class MFAStatusResponse(BaseModel):
    """Response showing user's MFA status."""
    is_enabled: bool = Field(..., description="Whether MFA is enabled")
    setup_completed: bool = Field(..., description="Whether MFA setup is completed")
    backup_codes_remaining: int = Field(..., description="Number of unused backup codes")
    last_used: Optional[datetime] = Field(None, description="Last time MFA was used")
    
    class Config:
        json_schema_extra = {
            "example": {
                "is_enabled": True,
                "setup_completed": True,
                "backup_codes_remaining": 6,
                "last_used": "2024-01-15T10:30:00Z"
            }
        }


class MFABackupCodesResponse(BaseModel):
    """Response with new backup codes."""
    backup_codes: List[str] = Field(..., description="List of new backup codes")
    codes_count: int = Field(..., description="Number of backup codes generated")
    
    class Config:
        json_schema_extra = {
            "example": {
                "backup_codes": ["123456789", "987654321", "456789123"],
                "codes_count": 8
            }
        }


class LoginWithMFARequest(BaseModel):
    """Login request that includes MFA token."""
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password")
    mfa_token: Optional[str] = Field(None, min_length=6, description="MFA token (TOTP or backup code)")
    
    @field_validator('mfa_token')
    @classmethod
    def validate_mfa_token(cls, v):
        """Validate MFA token format if provided."""
        if v and not (v.isdigit() and len(v) >= 6):
            raise ValueError('MFA token must be at least 6 digits')
        return v


class MFARequiredResponse(BaseModel):
    """Response when MFA is required for login."""
    message: str = Field(default="MFA token required")
    requires_mfa: bool = Field(default=True)
    temporary_token: str = Field(..., description="Temporary token for MFA completion")
    
    class Config:
        json_schema_extra = {
            "example": {
                "message": "MFA token required",
                "requires_mfa": True,
                "temporary_token": "temp_abc123xyz"
            }
        }


class CompleteMFALoginRequest(BaseModel):
    """Complete login with MFA token."""
    temporary_token: str = Field(..., description="Temporary token from initial login")
    mfa_token: str = Field(..., min_length=6, description="MFA token (TOTP or backup code)")
    
    @field_validator('mfa_token')
    @classmethod
    def validate_mfa_token(cls, v):
        """Validate MFA token format."""
        if not (v.isdigit() and len(v) >= 6):
            raise ValueError('MFA token must be at least 6 digits')
        return v


class MFAAttemptLog(BaseModel):
    """MFA attempt log entry."""
    id: str
    attempt_type: str = Field(..., description="Type of MFA attempt (totp/backup_code)")
    success: bool = Field(..., description="Whether the attempt was successful")
    ip_address: Optional[str] = Field(None, description="IP address of the attempt")
    user_agent: Optional[str] = Field(None, description="User agent of the attempt")
    created_at: datetime = Field(..., description="When the attempt was made")
    
    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "abc123",
                "attempt_type": "totp",
                "success": True,
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "created_at": "2024-01-15T10:30:00Z"
            }
        }