"""
PKCE (Proof Key for Code Exchange) Service for OAuth 2.1 Compliance
Implements RFC 7636 for enhanced OAuth security
"""

import base64
import hashlib
import secrets
import uuid
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import json

from app.config.redis_config import get_redis_client
from app.core.logging import get_logger

logger = get_logger(__name__)

class PKCEService:
    """
    Service for handling PKCE (Proof Key for Code Exchange) operations
    Required for OAuth 2.1 compliance and security
    """
    
    def __init__(self):
        self.redis_client = None
        self._ttl = 600  # 10 minutes TTL for PKCE data
    
    async def _get_redis(self):
        """Get Redis client with lazy initialization"""
        if self.redis_client is None:
            self.redis_client = await get_redis_client()
        return self.redis_client
    
    def generate_code_verifier(self, length: int = 128) -> str:
        """
        Generate cryptographically secure code verifier
        
        Args:
            length: Length of code verifier (43-128 chars per RFC 7636)
            
        Returns:
            Base64 URL-safe encoded random string
        """
        if not (43 <= length <= 128):
            raise ValueError("Code verifier length must be between 43 and 128 characters")
        
        # Generate random bytes and encode as base64url
        random_bytes = secrets.token_bytes(length)
        code_verifier = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
        
        # Remove padding and truncate to desired length
        code_verifier = code_verifier.rstrip('=')[:length]
        
        logger.debug(f"Generated code verifier with length: {len(code_verifier)}")
        return code_verifier
    
    def generate_code_challenge(self, verifier: str, method: str = "S256") -> str:
        """
        Generate code challenge from verifier using SHA256
        
        Args:
            verifier: Code verifier string
            method: Challenge method (S256 or plain)
            
        Returns:
            Base64 URL-safe encoded challenge string
        """
        if method == "S256":
            # Create SHA256 hash of verifier
            challenge_bytes = hashlib.sha256(verifier.encode('utf-8')).digest()
            # Encode as base64url without padding
            challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        elif method == "plain":
            challenge = verifier
        else:
            raise ValueError(f"Unsupported challenge method: {method}")
        
        logger.debug(f"Generated code challenge using method: {method}")
        return challenge
    
    async def store_pkce_data(
        self,
        state: str,
        verifier: str,
        challenge: str,
        method: str = "S256",
        provider: str = None,
        user_session: str = None
    ) -> None:
        """
        Store PKCE data in Redis with TTL
        
        Args:
            state: OAuth state parameter
            verifier: Code verifier
            challenge: Code challenge
            method: Challenge method
            provider: OAuth provider name
            user_session: User session ID for correlation
        """
        try:
            redis = await self._get_redis()
            
            pkce_data = {
                "verifier": verifier,
                "challenge": challenge,
                "method": method,
                "provider": provider,
                "user_session": user_session,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": (datetime.utcnow() + timedelta(seconds=self._ttl)).isoformat()
            }
            
            key = f"pkce:state:{state}"
            await redis.setex(key, self._ttl, json.dumps(pkce_data))
            
            logger.info(f"Stored PKCE data for state: {state[:8]}... (provider: {provider})")
            
            # Store reverse lookup for cleanup
            cleanup_key = f"pkce:cleanup:{int(datetime.utcnow().timestamp()) + self._ttl}"
            await redis.sadd(cleanup_key, state)
            await redis.expire(cleanup_key, self._ttl + 60)
            
        except Exception as e:
            logger.error(f"Failed to store PKCE data: {str(e)}")
            raise
    
    async def retrieve_pkce_data(self, state: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve PKCE data by state parameter
        
        Args:
            state: OAuth state parameter
            
        Returns:
            PKCE data dictionary or None if not found/expired
        """
        try:
            redis = await self._get_redis()
            key = f"pkce:state:{state}"
            
            data = await redis.get(key)
            if not data:
                logger.warning(f"PKCE data not found for state: {state[:8]}...")
                return None
            
            pkce_data = json.loads(data)
            
            # Check expiration
            expires_at = datetime.fromisoformat(pkce_data["expires_at"])
            if datetime.utcnow() > expires_at:
                logger.warning(f"PKCE data expired for state: {state[:8]}...")
                await redis.delete(key)
                return None
            
            logger.debug(f"Retrieved PKCE data for state: {state[:8]}...")
            return pkce_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve PKCE data: {str(e)}")
            return None
    
    async def validate_pkce(
        self,
        state: str,
        code_verifier: str,
        provider: str = None
    ) -> bool:
        """
        Validate PKCE code verifier against stored challenge
        
        Args:
            state: OAuth state parameter
            code_verifier: Code verifier from token exchange
            provider: OAuth provider for additional validation
            
        Returns:
            True if validation successful, False otherwise
        """
        try:
            # Retrieve stored PKCE data
            pkce_data = await self.retrieve_pkce_data(state)
            if not pkce_data:
                logger.warning(f"PKCE validation failed - no data for state: {state[:8]}...")
                return False
            
            # Validate provider if specified
            if provider and pkce_data.get("provider") != provider:
                logger.warning(f"PKCE validation failed - provider mismatch: {provider}")
                return False
            
            # Generate challenge from provided verifier
            expected_challenge = self.generate_code_challenge(
                code_verifier, 
                pkce_data.get("method", "S256")
            )
            
            # Compare challenges
            stored_challenge = pkce_data["challenge"]
            if expected_challenge != stored_challenge:
                logger.warning(f"PKCE validation failed - challenge mismatch for state: {state[:8]}...")
                return False
            
            # Clean up used PKCE data
            await self._cleanup_pkce_data(state)
            
            logger.info(f"PKCE validation successful for state: {state[:8]}... (provider: {provider})")
            return True
            
        except Exception as e:
            logger.error(f"PKCE validation error: {str(e)}")
            return False
    
    async def _cleanup_pkce_data(self, state: str) -> None:
        """Clean up PKCE data after successful validation"""
        try:
            redis = await self._get_redis()
            key = f"pkce:state:{state}"
            await redis.delete(key)
            logger.debug(f"Cleaned up PKCE data for state: {state[:8]}...")
        except Exception as e:
            logger.error(f"Failed to cleanup PKCE data: {str(e)}")
    
    async def cleanup_expired_pkce(self) -> int:
        """
        Clean up expired PKCE data
        
        Returns:
            Number of expired entries cleaned up
        """
        try:
            redis = await self._get_redis()
            current_time = int(datetime.utcnow().timestamp())
            cleaned_count = 0
            
            # Find cleanup keys that have expired
            pattern = "pkce:cleanup:*"
            async for key in redis.scan_iter(match=pattern):
                try:
                    timestamp = int(key.decode().split(":")[-1])
                    if timestamp <= current_time:
                        # Get states to cleanup
                        states = await redis.smembers(key)
                        
                        # Delete individual PKCE entries
                        for state in states:
                            state_key = f"pkce:state:{state.decode()}"
                            if await redis.delete(state_key):
                                cleaned_count += 1
                        
                        # Delete cleanup key
                        await redis.delete(key)
                        
                except Exception as e:
                    logger.error(f"Error processing cleanup key {key}: {str(e)}")
                    continue
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired PKCE entries")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired PKCE data: {str(e)}")
            return 0
    
    async def get_pkce_stats(self) -> Dict[str, Any]:
        """
        Get PKCE statistics for monitoring
        
        Returns:
            Dictionary with PKCE statistics
        """
        try:
            redis = await self._get_redis()
            
            # Count active PKCE entries
            pattern = "pkce:state:*"
            active_count = 0
            async for _ in redis.scan_iter(match=pattern):
                active_count += 1
            
            # Count cleanup keys
            cleanup_pattern = "pkce:cleanup:*"
            cleanup_count = 0
            async for _ in redis.scan_iter(match=cleanup_pattern):
                cleanup_count += 1
            
            return {
                "active_pkce_entries": active_count,
                "cleanup_batches": cleanup_count,
                "ttl_seconds": self._ttl,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get PKCE stats: {str(e)}")
            return {"error": str(e)}

# Global PKCE service instance
pkce_service = PKCEService()

async def get_pkce_service() -> PKCEService:
    """Get PKCE service instance"""
    return pkce_service