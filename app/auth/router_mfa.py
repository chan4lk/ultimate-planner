"""MFA (Multi-Factor Authentication) router implementation."""
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List
import io

from .schemas_mfa import (
    MFASetupRequest, MFASetupResponse, MFAVerifyRequest, MFAEnableRequest,
    MFADisableRequest, MFAStatusResponse, MFABackupCodesResponse, MFAAttemptLog
)
from .mfa_service import MFAService
from .dependencies import get_current_user
from ..models.user import User
from ..database import get_db

router = APIRouter(prefix="/auth/mfa", tags=["mfa"])


@router.post("/setup", response_model=MFASetupResponse, status_code=status.HTTP_200_OK)
async def setup_mfa(
    request: MFASetupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Setup MFA for the current user.
    
    This endpoint initializes MFA setup by generating:
    - A new TOTP secret key
    - Backup codes for recovery
    - QR code URL for authenticator app setup
    
    Returns the secret key and backup codes for the user to save.
    The user must verify the setup with `/mfa/enable` to activate MFA.
    """
    mfa_service = MFAService(db)
    return await mfa_service.setup_mfa(current_user.id)


@router.get("/qr-code")
async def get_qr_code(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get QR code image for TOTP setup.
    
    Returns a PNG image that can be scanned by authenticator apps
    like Google Authenticator, Authy, or 1Password.
    
    The QR code contains the TOTP secret configured for this user.
    """
    mfa_service = MFAService(db)
    qr_code_data = mfa_service.generate_qr_code(current_user.id)
    
    return StreamingResponse(
        io.BytesIO(qr_code_data),
        media_type="image/png",
        headers={"Content-Disposition": "inline; filename=mfa_qr_code.png"}
    )


@router.post("/verify", status_code=status.HTTP_200_OK)
async def verify_mfa_token(
    request_data: MFAVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify MFA token (TOTP or backup code).
    
    This endpoint can be used to:
    1. Test TOTP tokens during setup
    2. Verify tokens for sensitive operations
    3. Test backup codes
    
    Rate limited to prevent brute force attacks.
    """
    mfa_service = MFAService(db)
    
    # Try TOTP first, then backup code
    is_valid = (
        await mfa_service.verify_totp_token(current_user.id, request_data.token, request) or
        await mfa_service.verify_backup_code(current_user.id, request_data.token, request)
    )
    
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA token"
        )
    
    return {"message": "MFA token verified successfully", "valid": True}


@router.post("/enable", status_code=status.HTTP_200_OK)
async def enable_mfa(
    request_data: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enable MFA for the user after successful token verification.
    
    This permanently activates MFA for the user account.
    After enabling, the user will be required to provide MFA tokens for login.
    
    The provided token must be valid to confirm the user has properly
    configured their authenticator app.
    """
    mfa_service = MFAService(db)
    
    success = await mfa_service.enable_mfa(current_user.id, request_data.token)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token. Cannot enable MFA."
        )
    
    return {
        "message": "MFA enabled successfully",
        "enabled": True,
        "warning": "Save your backup codes in a secure location. You will need them if you lose access to your authenticator app."
    }


@router.post("/disable", status_code=status.HTTP_200_OK)
async def disable_mfa(
    request_data: MFADisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Disable MFA for the user.
    
    Requires:
    - Current password for security
    - Optional MFA token for additional security
    
    This will turn off MFA requirement for the user's account.
    """
    mfa_service = MFAService(db)
    
    success = await mfa_service.disable_mfa(
        current_user.id, 
        request_data.password, 
        request_data.token
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to disable MFA. Check password and MFA token."
        )
    
    return {
        "message": "MFA disabled successfully",
        "enabled": False
    }


@router.get("/status", response_model=MFAStatusResponse)
async def get_mfa_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current MFA status for the user.
    
    Returns information about:
    - Whether MFA is enabled
    - Whether setup is completed
    - Number of remaining backup codes
    - Last time MFA was used
    """
    mfa_service = MFAService(db)
    return await mfa_service.get_mfa_status(current_user.id)


@router.post("/backup-codes/regenerate", response_model=MFABackupCodesResponse)
async def regenerate_backup_codes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generate new backup codes for the user.
    
    This invalidates all existing backup codes and creates new ones.
    The user should save these codes in a secure location.
    
    Only available when MFA is enabled.
    """
    mfa_service = MFAService(db)
    return await mfa_service.regenerate_backup_codes(current_user.id)


@router.get("/attempts", response_model=List[MFAAttemptLog])
async def get_mfa_attempts(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get recent MFA verification attempts for security monitoring.
    
    Returns a list of recent MFA attempts including:
    - Attempt type (TOTP or backup code)
    - Success/failure status
    - IP address and user agent
    - Timestamp
    
    Useful for detecting suspicious activity.
    """
    if limit > 50:
        limit = 50  # Cap the limit for performance
    
    mfa_service = MFAService(db)
    return await mfa_service.get_recent_attempts(current_user.id, limit)