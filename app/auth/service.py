from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import Optional, Union, Dict, Any
from fastapi import HTTPException, status, Request
from .security import verify_password, get_password_hash, create_access_token
from .schemas import UserCreate, UserLogin
from .schemas_mfa import LoginWithMFARequest, MFARequiredResponse, CompleteMFALoginRequest
from ..models.user import User
from ..database import get_db


class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        # Check if user already exists
        existing_user = self.db.execute(
            select(User).where(
                (User.email == user_data.email) | (User.username == user_data.username)
            )
        ).scalar_one_or_none()
        
        if existing_user:
            if existing_user.email == user_data.email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )

        # Create new user
        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            email=user_data.email,
            username=user_data.username,
            hashed_password=hashed_password
        )
        
        self.db.add(db_user)
        self.db.commit()
        self.db.refresh(db_user)
        return db_user

    def authenticate_user(self, login_data: UserLogin) -> Optional[User]:
        """Authenticate user with email and password."""
        user = self.db.execute(
            select(User).where(User.email == login_data.email)
        ).scalar_one_or_none()
        
        if not user:
            return None
        
        if not verify_password(login_data.password, user.hashed_password):
            return None
        
        if not user.is_active:
            return None
            
        return user

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.db.execute(
            select(User).where(User.id == user_id)
        ).scalar_one_or_none()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        return self.db.execute(
            select(User).where(User.email == email)
        ).scalar_one_or_none()

    def login_user(self, login_data: UserLogin) -> str:
        """Login user and return access token (legacy method - no MFA)."""
        user = self.authenticate_user(login_data)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token = create_access_token(data={"sub": user.id})
        return access_token
    
    async def login_user_with_session(
        self,
        login_data: UserLogin,
        request: Optional[Request] = None,
        remember_me: bool = False
    ) -> Dict[str, Any]:
        """Login user with Redis session management."""
        from ..services.jwt_service import JWTService
        
        user = self.authenticate_user(login_data)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        jwt_service = JWTService()
        return await jwt_service.create_session_with_token(
            user_id=str(user.id),
            request=request,
            remember_me=remember_me
        )
    
    async def login_with_mfa(
        self, 
        login_data: LoginWithMFARequest, 
        request: Optional[Request] = None
    ) -> Union[Dict[str, Any], MFARequiredResponse]:
        """
        Enhanced login that handles MFA requirements.
        
        Returns either:
        - Full login response with access token (if no MFA or MFA provided)
        - MFA required response with temporary token (if MFA enabled but not provided)
        """
        # First authenticate with email/password
        basic_login = UserLogin(email=login_data.email, password=login_data.password)
        user = self.authenticate_user(basic_login)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check if user has MFA enabled
        if not user.has_mfa_enabled:
            # No MFA required, proceed with normal login
            access_token = create_access_token(data={"sub": user.id})
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "mfa_required": False
            }
        
        # MFA is enabled, check if token was provided
        if not login_data.mfa_token:
            # MFA token required but not provided
            from .mfa_service import MFAService
            mfa_service = MFAService(self.db)
            temp_token = mfa_service.create_temporary_mfa_token(user.id)
            
            return MFARequiredResponse(
                message="MFA token required",
                requires_mfa=True,
                temporary_token=temp_token
            )
        
        # MFA token provided, verify it
        from .mfa_service import MFAService
        mfa_service = MFAService(self.db)
        
        # Try TOTP first, then backup code
        mfa_valid = (
            await mfa_service.verify_totp_token(user.id, login_data.mfa_token, request) or
            await mfa_service.verify_backup_code(user.id, login_data.mfa_token, request)
        )
        
        if not mfa_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # MFA verified, complete login
        access_token = create_access_token(data={"sub": user.id})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "mfa_required": False,
            "mfa_verified": True
        }
    
    async def complete_mfa_login(
        self, 
        request_data: CompleteMFALoginRequest, 
        request: Optional[Request] = None
    ) -> Dict[str, Any]:
        """Complete MFA login using temporary token."""
        from .mfa_service import MFAService
        mfa_service = MFAService(self.db)
        
        # Verify temporary token and get user_id
        user_id = mfa_service.verify_temporary_mfa_token(request_data.temporary_token)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired temporary token"
            )
        
        # Verify MFA token
        mfa_valid = (
            await mfa_service.verify_totp_token(user_id, request_data.mfa_token, request) or
            await mfa_service.verify_backup_code(user_id, request_data.mfa_token, request)
        )
        
        if not mfa_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token"
            )
        
        # Create full access token
        access_token = create_access_token(data={"sub": user_id})
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "mfa_verified": True
        }