from fastapi import Depends, HTTPException, status, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
from .security import verify_token
from .service import AuthService
from ..models.user import User
from ..database import get_db
from ..services.jwt_service import JWTService

# Security scheme
security = HTTPBearer()


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID")
) -> User:
    """Get current authenticated user with Redis session validation."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        jwt_service = JWTService()
        
        # Verify token with optional session validation
        payload = await jwt_service.validate_token_with_session(token, x_session_id)
        if payload is None:
            raise credentials_exception
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        
        # Update session activity if session_id provided
        if x_session_id:
            await jwt_service.redis_session.update_session_activity(x_session_id)
            
    except Exception:
        raise credentials_exception
    
    auth_service = AuthService(db)
    user = auth_service.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_optional_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID")
) -> Optional[User]:
    """Get current user if authenticated, otherwise return None."""
    if not credentials:
        return None
    
    try:
        token = credentials.credentials
        jwt_service = JWTService()
        
        # Verify token with optional session validation
        payload = await jwt_service.validate_token_with_session(token, x_session_id)
        if payload is None:
            return None
        
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
        
        # Update session activity if session_id provided
        if x_session_id:
            await jwt_service.redis_session.update_session_activity(x_session_id)
            
        auth_service = AuthService(db)
        user = auth_service.get_user_by_id(user_id)
        return user if user and user.is_active else None
        
    except Exception:
        return None


# Legacy sync dependency for backward compatibility
def get_current_user_sync(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user (legacy sync version)."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = verify_token(token)
        if payload is None:
            raise credentials_exception
        
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
            
    except Exception:
        raise credentials_exception
    
    auth_service = AuthService(db)
    user = auth_service.get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    return user


def get_session_from_headers(
    x_session_id: Optional[str] = Header(None, alias="X-Session-ID")
) -> Optional[str]:
    """Extract session ID from headers."""
    return x_session_id