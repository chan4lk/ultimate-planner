"""MFA (Multi-Factor Authentication) service implementation."""
import pyotp
import qrcode
import secrets
import json
import io
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, func, desc
from fastapi import HTTPException, status, Request

from ..models.mfa import UserMFASecret, UserMFAAttempt
from ..models.user import User
from .security import encrypt_sensitive_data, decrypt_sensitive_data, create_access_token
from .schemas_mfa import MFASetupResponse, MFAStatusResponse, MFABackupCodesResponse, MFAAttemptLog


class MFAService:
    """Service for handling Multi-Factor Authentication operations."""
    
    # Rate limiting configuration
    MAX_ATTEMPTS_PER_HOUR = 10
    MAX_ATTEMPTS_PER_DAY = 50
    BACKUP_CODES_COUNT = 8
    BACKUP_CODE_LENGTH = 10
    
    def __init__(self, db: Session):
        self.db = db
    
    async def setup_mfa(self, user_id: str, app_name: str = "Ultimate Planner") -> MFASetupResponse:
        """Initialize MFA setup for user and return secret key with backup codes."""
        user = self.db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check if user already has MFA setup
        existing_mfa = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if existing_mfa and existing_mfa.is_enabled:
            raise HTTPException(
                status_code=400,
                detail="MFA is already enabled. Disable it first to reconfigure."
            )
        
        # Generate new TOTP secret
        secret = pyotp.random_base32()
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        backup_codes_encrypted = encrypt_sensitive_data(json.dumps(backup_codes))
        
        # Encrypt the secret
        secret_encrypted = encrypt_sensitive_data(secret)
        
        if existing_mfa:
            # Update existing record
            existing_mfa.secret_key = secret_encrypted
            existing_mfa.backup_codes = backup_codes_encrypted
            existing_mfa.is_enabled = False
            existing_mfa.updated_at = datetime.now(timezone.utc)
        else:
            # Create new MFA record
            mfa_secret = UserMFASecret(
                user_id=user_id,
                secret_key=secret_encrypted,
                backup_codes=backup_codes_encrypted,
                is_enabled=False
            )
            self.db.add(mfa_secret)
        
        self.db.commit()
        
        # Generate QR code URL
        qr_code_url = f"/auth/mfa/qr-code"
        
        return MFASetupResponse(
            secret_key=secret,
            qr_code_url=qr_code_url,
            backup_codes=backup_codes
        )
    
    def generate_qr_code(self, user_id: str, app_name: str = "Ultimate Planner") -> bytes:
        """Generate QR code for TOTP setup."""
        user = self.db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret:
            raise HTTPException(status_code=404, detail="MFA not set up for this user")
        
        # Decrypt secret
        secret = decrypt_sensitive_data(mfa_secret.secret_key)
        if not secret:
            raise HTTPException(status_code=500, detail="Failed to decrypt MFA secret")
        
        # Create TOTP URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name=app_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)
        
        return img_buffer.read()
    
    async def verify_totp_token(
        self, 
        user_id: str, 
        token: str, 
        request: Optional[Request] = None
    ) -> bool:
        """Verify TOTP token for user."""
        # Rate limiting check
        if not await self._check_rate_limit(user_id, request):
            raise HTTPException(
                status_code=429,
                detail="Too many MFA verification attempts. Please try again later."
            )
        
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret:
            await self._log_mfa_attempt(user_id, "totp", False, request)
            return False
        
        # Decrypt secret
        secret = decrypt_sensitive_data(mfa_secret.secret_key)
        if not secret:
            await self._log_mfa_attempt(user_id, "totp", False, request)
            return False
        
        # Verify TOTP token
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(token, valid_window=1)  # Allow 30 seconds window
        
        # Log attempt
        await self._log_mfa_attempt(user_id, "totp", is_valid, request)
        
        if is_valid:
            # Update last used timestamp
            mfa_secret.last_used_at = datetime.now(timezone.utc)
            self.db.commit()
        
        return is_valid
    
    async def verify_backup_code(
        self, 
        user_id: str, 
        code: str, 
        request: Optional[Request] = None
    ) -> bool:
        """Verify and consume backup code."""
        # Rate limiting check
        if not await self._check_rate_limit(user_id, request):
            raise HTTPException(
                status_code=429,
                detail="Too many MFA verification attempts. Please try again later."
            )
        
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret or not mfa_secret.backup_codes:
            await self._log_mfa_attempt(user_id, "backup_code", False, request)
            return False
        
        # Decrypt and parse backup codes
        backup_codes_data = decrypt_sensitive_data(mfa_secret.backup_codes)
        if not backup_codes_data:
            await self._log_mfa_attempt(user_id, "backup_code", False, request)
            return False
        
        try:
            backup_codes = json.loads(backup_codes_data)
        except json.JSONDecodeError:
            await self._log_mfa_attempt(user_id, "backup_code", False, request)
            return False
        
        # Check if code exists and is unused
        is_valid = code in backup_codes
        
        if is_valid:
            # Remove used backup code
            backup_codes.remove(code)
            
            # Encrypt and save updated backup codes
            updated_codes = encrypt_sensitive_data(json.dumps(backup_codes))
            mfa_secret.backup_codes = updated_codes
            mfa_secret.last_used_at = datetime.now(timezone.utc)
            self.db.commit()
        
        # Log attempt
        await self._log_mfa_attempt(user_id, "backup_code", is_valid, request)
        
        return is_valid
    
    async def enable_mfa(self, user_id: str, verification_token: str) -> bool:
        """Enable MFA after successful token verification."""
        # Verify token first
        if not await self.verify_totp_token(user_id, verification_token):
            return False
        
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret:
            return False
        
        mfa_secret.is_enabled = True
        mfa_secret.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        
        return True
    
    async def disable_mfa(self, user_id: str, password: str, mfa_token: Optional[str] = None) -> bool:
        """Disable MFA after password and optional MFA verification."""
        user = self.db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not user:
            return False
        
        # Verify password
        from .security import verify_password
        if not verify_password(password, user.hashed_password):
            return False
        
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret or not mfa_secret.is_enabled:
            return False
        
        # If MFA token provided, verify it
        if mfa_token:
            # Try TOTP first, then backup code
            token_valid = (
                await self.verify_totp_token(user_id, mfa_token) or
                await self.verify_backup_code(user_id, mfa_token)
            )
            if not token_valid:
                return False
        
        # Disable MFA
        mfa_secret.is_enabled = False
        mfa_secret.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        
        return True
    
    async def get_mfa_status(self, user_id: str) -> MFAStatusResponse:
        """Get MFA status for user."""
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret:
            return MFAStatusResponse(
                is_enabled=False,
                setup_completed=False,
                backup_codes_remaining=0,
                last_used=None
            )
        
        # Count remaining backup codes
        backup_codes_count = 0
        if mfa_secret.backup_codes:
            backup_codes_data = decrypt_sensitive_data(mfa_secret.backup_codes)
            if backup_codes_data:
                try:
                    backup_codes = json.loads(backup_codes_data)
                    backup_codes_count = len(backup_codes)
                except json.JSONDecodeError:
                    pass
        
        return MFAStatusResponse(
            is_enabled=mfa_secret.is_enabled,
            setup_completed=bool(mfa_secret.secret_key),
            backup_codes_remaining=backup_codes_count,
            last_used=mfa_secret.last_used_at
        )
    
    async def regenerate_backup_codes(self, user_id: str) -> MFABackupCodesResponse:
        """Generate new backup codes for user."""
        mfa_secret = self.db.execute(
            select(UserMFASecret).where(UserMFASecret.user_id == user_id)
        ).scalar_one_or_none()
        
        if not mfa_secret or not mfa_secret.is_enabled:
            raise HTTPException(
                status_code=400,
                detail="MFA must be enabled to regenerate backup codes"
            )
        
        # Generate new backup codes
        backup_codes = self._generate_backup_codes()
        backup_codes_encrypted = encrypt_sensitive_data(json.dumps(backup_codes))
        
        # Update in database
        mfa_secret.backup_codes = backup_codes_encrypted
        mfa_secret.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        
        return MFABackupCodesResponse(
            backup_codes=backup_codes,
            codes_count=len(backup_codes)
        )
    
    async def get_recent_attempts(self, user_id: str, limit: int = 10) -> List[MFAAttemptLog]:
        """Get recent MFA attempts for user."""
        attempts = self.db.execute(
            select(UserMFAAttempt)
            .where(UserMFAAttempt.user_id == user_id)
            .order_by(desc(UserMFAAttempt.created_at))
            .limit(limit)
        ).scalars().all()
        
        return [
            MFAAttemptLog(
                id=attempt.id,
                attempt_type=attempt.attempt_type,
                success=attempt.success,
                ip_address=attempt.ip_address,
                user_agent=attempt.user_agent,
                created_at=attempt.created_at
            )
            for attempt in attempts
        ]
    
    def _generate_backup_codes(self) -> List[str]:
        """Generate secure backup codes."""
        codes = []
        for _ in range(self.BACKUP_CODES_COUNT):
            code = ''.join([str(secrets.randbelow(10)) for _ in range(self.BACKUP_CODE_LENGTH)])
            codes.append(code)
        return codes
    
    async def _check_rate_limit(self, user_id: str, request: Optional[Request] = None) -> bool:
        """Check if user has exceeded MFA attempt rate limits."""
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        # Count attempts in the last hour
        hour_attempts = self.db.execute(
            select(func.count(UserMFAAttempt.id))
            .where(and_(
                UserMFAAttempt.user_id == user_id,
                UserMFAAttempt.created_at >= hour_ago
            ))
        ).scalar()
        
        if hour_attempts >= self.MAX_ATTEMPTS_PER_HOUR:
            return False
        
        # Count attempts in the last day
        day_attempts = self.db.execute(
            select(func.count(UserMFAAttempt.id))
            .where(and_(
                UserMFAAttempt.user_id == user_id,
                UserMFAAttempt.created_at >= day_ago
            ))
        ).scalar()
        
        if day_attempts >= self.MAX_ATTEMPTS_PER_DAY:
            return False
        
        return True
    
    async def _log_mfa_attempt(
        self, 
        user_id: str, 
        attempt_type: str, 
        success: bool, 
        request: Optional[Request] = None
    ) -> None:
        """Log MFA verification attempt."""
        ip_address = None
        user_agent = None
        
        if request:
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")
        
        attempt = UserMFAAttempt(
            user_id=user_id,
            attempt_type=attempt_type,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.db.add(attempt)
        self.db.commit()
    
    def create_temporary_mfa_token(self, user_id: str) -> str:
        """Create temporary token for MFA completion during login."""
        # Create short-lived token (5 minutes)
        expire_delta = timedelta(minutes=5)
        token_data = {
            "sub": user_id,
            "type": "mfa_temp",
            "scope": "mfa_completion"
        }
        return create_access_token(data=token_data, expires_delta=expire_delta)
    
    def verify_temporary_mfa_token(self, token: str) -> Optional[str]:
        """Verify temporary MFA token and return user_id."""
        from .security import verify_token
        
        payload = verify_token(token)
        if not payload:
            return None
        
        if payload.get("type") != "mfa_temp":
            return None
        
        return payload.get("sub")