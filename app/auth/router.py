from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Union, Dict, Any
from .schemas import UserCreate, UserLogin, UserResponse, Token
from .schemas_mfa import LoginWithMFARequest, MFARequiredResponse, CompleteMFALoginRequest
from .service import AuthService
from .dependencies import security
from .router_mfa import router as mfa_router
from ..database import get_db

router = APIRouter(prefix="/auth", tags=["authentication"])

# Include MFA routes
router.include_router(mfa_router)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    """Register a new user."""
    auth_service = AuthService(db)
    user = auth_service.create_user(user_data)
    return user


@router.post("/login", response_model=Token)
def login_user(
    login_data: UserLogin,
    db: Session = Depends(get_db)
):
    """Login user and return access token (legacy - no MFA support)."""
    auth_service = AuthService(db)
    access_token = auth_service.login_user(login_data)
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login-mfa", response_model=Union[Dict[str, Any], MFARequiredResponse])
async def login_user_with_mfa(
    login_data: LoginWithMFARequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Enhanced login endpoint with MFA support.
    
    This endpoint handles both regular login and MFA-enabled accounts:
    - If user has no MFA: returns access token immediately
    - If user has MFA but no token provided: returns temporary token for MFA completion
    - If user has MFA and token provided: verifies MFA and returns access token
    
    For MFA-enabled accounts without token, use the temporary_token with /auth/complete-mfa endpoint.
    """
    auth_service = AuthService(db)
    return await auth_service.login_with_mfa(login_data, request)


@router.post("/complete-mfa", response_model=Dict[str, Any])
async def complete_mfa_login(
    request_data: CompleteMFALoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Complete MFA login using temporary token.
    
    After receiving a temporary_token from /auth/login-mfa, use this endpoint
    to complete the login process by providing a valid MFA token.
    
    Returns the final access token upon successful MFA verification.
    """
    auth_service = AuthService(db)
    return await auth_service.complete_mfa_login(request_data, request)


@router.post("/logout", status_code=status.HTTP_200_OK)
def logout_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Logout user and invalidate token."""
    from .security import blacklist_token
    
    # Blacklist the current token
    token = credentials.credentials
    blacklist_token(token)
    
    return {"message": "Successfully logged out"}


# Define the endpoint after importing the dependency
def _setup_me_endpoint():
    from .dependencies import get_current_user
    from ..models.user import User
    
    @router.get("/me", response_model=UserResponse)
    def get_current_user_info(
        current_user: User = Depends(get_current_user)
    ):
        """Get current user information."""
        return current_user

# Call the setup function
_setup_me_endpoint()