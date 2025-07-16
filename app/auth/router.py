from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from .schemas import UserCreate, UserLogin, UserResponse, Token
from .service import AuthService
from .dependencies import security
from ..database import get_db

router = APIRouter(prefix="/auth", tags=["authentication"])


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
    """Login user and return access token."""
    auth_service = AuthService(db)
    access_token = auth_service.login_user(login_data)
    return {"access_token": access_token, "token_type": "bearer"}


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