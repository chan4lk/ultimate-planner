from datetime import datetime, timedelta, timezone
from typing import Optional, Set
from jose import JWTError, jwt
from passlib.context import CryptContext
from passlib.hash import bcrypt
from cryptography.fernet import Fernet
import os
import base64
from dotenv import load_dotenv

load_dotenv()

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# Encryption key for sensitive data (in production, this should be stored securely)
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # Generate a key if not provided (for development only)
    ENCRYPTION_KEY = base64.urlsafe_b64encode(os.urandom(32)).decode()

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Encryption context for sensitive data
fernet = Fernet(ENCRYPTION_KEY.encode() if len(ENCRYPTION_KEY) == 44 else base64.urlsafe_b64encode(ENCRYPTION_KEY.encode()[:32]))

# Token blacklist (in production, this should be stored in Redis or database)
_token_blacklist: Set[str] = set()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    """Verify and decode JWT token."""
    # Check if token is blacklisted
    if is_token_blacklisted(token):
        return None
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def extract_user_id_from_token(token: str) -> Optional[str]:
    """Extract user ID from JWT token."""
    payload = verify_token(token)
    if payload:
        return payload.get("sub")
    return None


def blacklist_token(token: str) -> None:
    """Add token to blacklist (legacy - use Redis service for new implementations)."""
    _token_blacklist.add(token)


def is_token_blacklisted(token: str) -> bool:
    """Check if token is blacklisted (legacy - use Redis service for new implementations)."""
    return token in _token_blacklist


async def blacklist_token_redis(token_jti: str, expire_seconds: int = None) -> bool:
    """Add JWT token to Redis blacklist."""
    from ..services.redis_session_service import RedisSessionService
    redis_session = RedisSessionService()
    return await redis_session.blacklist_token(token_jti, expire_seconds)


async def is_token_blacklisted_redis(token_jti: str) -> bool:
    """Check if JWT token is blacklisted in Redis."""
    from ..services.redis_session_service import RedisSessionService
    redis_session = RedisSessionService()
    return await redis_session.is_token_blacklisted(token_jti)


def clear_token_blacklist() -> None:
    """Clear token blacklist (for testing purposes)."""
    _token_blacklist.clear()


def encrypt_sensitive_data(data: str) -> str:
    """Encrypt sensitive data using Fernet encryption."""
    if not data:
        return data
    return fernet.encrypt(data.encode()).decode()


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """Decrypt sensitive data using Fernet encryption."""
    if not encrypted_data:
        return encrypted_data
    try:
        return fernet.decrypt(encrypted_data.encode()).decode()
    except Exception:
        # Return empty string if decryption fails
        return ""