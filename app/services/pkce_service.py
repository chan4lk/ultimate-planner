"""
PKCE (Proof Key for Code Exchange) service implementation for OAuth 2.1 compliance.
RFC 7636: https://tools.ietf.org/html/rfc7636
"""
import hashlib
import secrets
import base64
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass

import aioredis
from aioredis import Redis

from ..config.redis_config import get_redis_connection


# Configure logging for security audit
logger = logging.getLogger(__name__)


@dataclass
class PKCEData:
    """PKCE data container."""
    code_verifier: str
    code_challenge: str
    code_challenge_method: str
    state: str
    created_at: datetime
    expires_at: datetime
    
    def is_expired(self) -> bool:
        """Check if PKCE data is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Redis storage."""
        return {
            "code_verifier": self.code_verifier,
            "code_challenge": self.code_challenge,
            "code_challenge_method": self.code_challenge_method,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PKCEData":
        """Create from dictionary retrieved from Redis."""
        return cls(
            code_verifier=data["code_verifier"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            state=data["state"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"])
        )


class PKCEService:
    """
    PKCE service for OAuth 2.1 compliance.
    
    Implements Proof Key for Code Exchange (RFC 7636) to prevent
    authorization code interception attacks.
    """
    
    # Redis key prefix for PKCE data storage
    PKCE_REDIS_PREFIX = "pkce:state"
    
    # PKCE configuration constants
    CODE_VERIFIER_LENGTH = 128  # 43-128 characters allowed, using max for security
    CODE_CHALLENGE_METHOD = "S256"  # SHA256 method (required by OAuth 2.1)
    PKCE_TTL_SECONDS = 600  # 10 minutes
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """
        Initialize PKCE service.
        
        Args:
            redis_client: Optional Redis client. If None, will get from config.
        """
        self.redis = redis_client
        self._ensure_redis_connection()
    
    async def _ensure_redis_connection(self) -> None:
        """Ensure Redis connection is available."""
        if self.redis is None:
            self.redis = await get_redis_connection()
    
    def generate_code_verifier(self) -> str:
        """
        Generate cryptographically secure code verifier.
        
        Returns:
            Base64 URL-safe encoded random string (128 characters).
        """
        # Generate random bytes
        random_bytes = secrets.token_bytes(96)  # 96 bytes = 128 base64 chars
        
        # Encode as base64 URL-safe string
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('ascii')
        
        # Remove padding to ensure clean URL parameter
        code_verifier = code_verifier.rstrip('=')
        
        logger.info("Generated PKCE code verifier", extra={"length": len(code_verifier)})
        
        return code_verifier
    
    def generate_code_challenge(self, code_verifier: str) -> str:
        """
        Generate code challenge from code verifier using SHA256.
        
        Args:
            code_verifier: The code verifier string.
            
        Returns:
            Base64 URL-safe encoded SHA256 hash of the code verifier.
        """
        # Create SHA256 hash of the code verifier
        sha256_hash = hashlib.sha256(code_verifier.encode('ascii')).digest()
        
        # Encode as base64 URL-safe string
        code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('ascii')
        
        # Remove padding
        code_challenge = code_challenge.rstrip('=')
        
        logger.info("Generated PKCE code challenge", extra={
            "method": self.CODE_CHALLENGE_METHOD,
            "challenge_length": len(code_challenge)
        })
        
        return code_challenge
    
    async def generate_pkce_data(self, state: str) -> PKCEData:
        """
        Generate complete PKCE data for OAuth flow.
        
        Args:
            state: OAuth state parameter to correlate with PKCE data.
            
        Returns:
            PKCEData containing verifier, challenge, and metadata.
        """
        await self._ensure_redis_connection()
        
        # Generate code verifier
        code_verifier = self.generate_code_verifier()
        
        # Generate code challenge
        code_challenge = self.generate_code_challenge(code_verifier)
        
        # Create PKCE data with timestamps
        now = datetime.now(timezone.utc)
        pkce_data = PKCEData(
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            code_challenge_method=self.CODE_CHALLENGE_METHOD,
            state=state,
            created_at=now,
            expires_at=now + timedelta(seconds=self.PKCE_TTL_SECONDS)
        )
        
        logger.info("Generated PKCE data for OAuth flow", extra={
            "state": state,
            "expires_at": pkce_data.expires_at.isoformat()
        })
        
        return pkce_data
    
    async def store_pkce_data(self, state: str, pkce_data: PKCEData) -> None:
        """
        Store PKCE data in Redis with TTL.
        
        Args:
            state: OAuth state parameter used as key correlation.
            pkce_data: PKCE data to store.
        """
        await self._ensure_redis_connection()
        
        redis_key = f"{self.PKCE_REDIS_PREFIX}:{state}"
        
        # Store as hash with TTL
        await self.redis.hset(redis_key, mapping=pkce_data.to_dict())
        await self.redis.expire(redis_key, self.PKCE_TTL_SECONDS)
        
        logger.info("Stored PKCE data in Redis", extra={
            "state": state,
            "redis_key": redis_key,
            "ttl_seconds": self.PKCE_TTL_SECONDS
        })
    
    async def retrieve_pkce_data(self, state: str) -> Optional[PKCEData]:
        """
        Retrieve PKCE data from Redis by state.
        
        Args:
            state: OAuth state parameter.
            
        Returns:
            PKCEData if found and not expired, None otherwise.
        """
        await self._ensure_redis_connection()
        
        redis_key = f"{self.PKCE_REDIS_PREFIX}:{state}"
        
        # Retrieve data from Redis
        data = await self.redis.hgetall(redis_key)
        
        if not data:
            logger.warning("PKCE data not found", extra={"state": state})
            return None
        
        # Convert bytes to strings (Redis returns bytes)
        str_data = {k.decode() if isinstance(k, bytes) else k: 
                   v.decode() if isinstance(v, bytes) else v 
                   for k, v in data.items()}
        
        # Create PKCEData object
        pkce_data = PKCEData.from_dict(str_data)
        
        # Check expiration
        if pkce_data.is_expired():
            logger.warning("PKCE data expired", extra={
                "state": state,
                "expired_at": pkce_data.expires_at.isoformat()
            })
            # Clean up expired data
            await self.cleanup_pkce_data(state)
            return None
        
        logger.info("Retrieved PKCE data from Redis", extra={"state": state})
        
        return pkce_data
    
    async def validate_pkce(self, state: str, code_verifier: str) -> bool:
        """
        Validate PKCE code verifier against stored challenge.
        
        Args:
            state: OAuth state parameter.
            code_verifier: Code verifier to validate.
            
        Returns:
            True if validation succeeds, False otherwise.
        """
        # Retrieve stored PKCE data
        pkce_data = await self.retrieve_pkce_data(state)
        
        if pkce_data is None:
            logger.error("PKCE validation failed - no data found", extra={"state": state})
            return False
        
        # Generate challenge from provided verifier
        expected_challenge = self.generate_code_challenge(code_verifier)
        
        # Compare challenges
        is_valid = secrets.compare_digest(expected_challenge, pkce_data.code_challenge)
        
        if is_valid:
            logger.info("PKCE validation successful", extra={"state": state})
            # Clean up used PKCE data
            await self.cleanup_pkce_data(state)
        else:
            logger.error("PKCE validation failed - challenge mismatch", extra={
                "state": state,
                "expected_challenge": expected_challenge[:10] + "...",  # Log partial for debugging
                "stored_challenge": pkce_data.code_challenge[:10] + "..."
            })
        
        return is_valid
    
    async def cleanup_pkce_data(self, state: str) -> None:
        """
        Clean up PKCE data for a specific state.
        
        Args:
            state: OAuth state parameter.
        """
        await self._ensure_redis_connection()
        
        redis_key = f"{self.PKCE_REDIS_PREFIX}:{state}"
        deleted = await self.redis.delete(redis_key)
        
        if deleted:
            logger.info("Cleaned up PKCE data", extra={"state": state})
        else:
            logger.debug("No PKCE data to clean up", extra={"state": state})
    
    async def cleanup_expired_pkce(self) -> int:
        """
        Clean up all expired PKCE data.
        
        Returns:
            Number of expired entries cleaned up.
        """
        await self._ensure_redis_connection()
        
        # Get all PKCE keys
        pattern = f"{self.PKCE_REDIS_PREFIX}:*"
        keys = await self.redis.keys(pattern)
        
        expired_count = 0
        current_time = datetime.now(timezone.utc)
        
        for key in keys:
            # Check if key still exists (might have expired)
            if await self.redis.exists(key):
                # Get expiration info
                data = await self.redis.hgetall(key)
                if data:
                    str_data = {k.decode() if isinstance(k, bytes) else k: 
                               v.decode() if isinstance(v, bytes) else v 
                               for k, v in data.items()}
                    
                    try:
                        expires_at = datetime.fromisoformat(str_data["expires_at"])
                        if current_time > expires_at:
                            await self.redis.delete(key)
                            expired_count += 1
                    except (KeyError, ValueError):
                        # Invalid data, delete it
                        await self.redis.delete(key)
                        expired_count += 1
        
        if expired_count > 0:
            logger.info("Cleaned up expired PKCE entries", extra={
                "expired_count": expired_count
            })
        
        return expired_count
    
    async def get_pkce_statistics(self) -> Dict[str, Any]:
        """
        Get PKCE service statistics for monitoring.
        
        Returns:
            Dictionary with statistics about stored PKCE data.
        """
        await self._ensure_redis_connection()
        
        # Get all PKCE keys
        pattern = f"{self.PKCE_REDIS_PREFIX}:*"
        keys = await self.redis.keys(pattern)
        
        total_entries = len(keys)
        expired_entries = 0
        current_time = datetime.now(timezone.utc)
        
        for key in keys:
            if await self.redis.exists(key):
                data = await self.redis.hgetall(key)
                if data:
                    str_data = {k.decode() if isinstance(k, bytes) else k: 
                               v.decode() if isinstance(v, bytes) else v 
                               for k, v in data.items()}
                    
                    try:
                        expires_at = datetime.fromisoformat(str_data["expires_at"])
                        if current_time > expires_at:
                            expired_entries += 1
                    except (KeyError, ValueError):
                        expired_entries += 1
        
        return {
            "total_entries": total_entries,
            "active_entries": total_entries - expired_entries,
            "expired_entries": expired_entries,
            "ttl_seconds": self.PKCE_TTL_SECONDS,
            "code_challenge_method": self.CODE_CHALLENGE_METHOD,
            "code_verifier_length": self.CODE_VERIFIER_LENGTH
        }


# Global PKCE service instance
_pkce_service: Optional[PKCEService] = None


async def get_pkce_service() -> PKCEService:
    """Get the global PKCE service instance."""
    global _pkce_service
    
    if _pkce_service is None:
        _pkce_service = PKCEService()
        await _pkce_service._ensure_redis_connection()
    
    return _pkce_service