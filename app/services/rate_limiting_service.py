"""
Comprehensive Rate Limiting Service for Authentication Security
Prevents brute force attacks and abuse of authentication endpoints
"""

import time
import json
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import hashlib

from app.config.redis_config import get_redis_client
from app.core.logging import get_logger

logger = get_logger(__name__)

class RateLimitType(str, Enum):
    """Rate limit types for different authentication operations"""
    LOGIN_ATTEMPT = "login_attempt"
    MFA_VERIFICATION = "mfa_verification"
    PASSWORD_RESET = "password_reset"
    OAUTH_AUTHORIZATION = "oauth_authorization"
    TOKEN_REFRESH = "token_refresh"
    REGISTRATION = "registration"
    PKCE_GENERATION = "pkce_generation"
    SESSION_CREATION = "session_creation"

@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    requests: int  # Number of requests allowed
    window: int    # Time window in seconds
    block_duration: int  # Block duration in seconds after limit exceeded
    
class RateLimitResult:
    """Result of rate limit check"""
    def __init__(self, allowed: bool, remaining: int, reset_time: int, retry_after: int = None):
        self.allowed = allowed
        self.remaining = remaining
        self.reset_time = reset_time
        self.retry_after = retry_after  # Seconds until next request allowed

class RateLimitingService:
    """
    Comprehensive rate limiting service for authentication security
    """
    
    def __init__(self):
        self.redis_client = None
        
        # Default rate limiting rules
        self.default_rules = {
            RateLimitType.LOGIN_ATTEMPT: RateLimitRule(5, 300, 900),      # 5 attempts per 5 minutes, block 15 minutes
            RateLimitType.MFA_VERIFICATION: RateLimitRule(10, 3600, 1800), # 10 attempts per hour, block 30 minutes
            RateLimitType.PASSWORD_RESET: RateLimitRule(3, 3600, 3600),   # 3 attempts per hour, block 1 hour
            RateLimitType.OAUTH_AUTHORIZATION: RateLimitRule(20, 300, 300), # 20 attempts per 5 minutes, block 5 minutes
            RateLimitType.TOKEN_REFRESH: RateLimitRule(100, 3600, 600),   # 100 refreshes per hour, block 10 minutes
            RateLimitType.REGISTRATION: RateLimitRule(3, 3600, 7200),     # 3 registrations per hour, block 2 hours
            RateLimitType.PKCE_GENERATION: RateLimitRule(50, 300, 300),   # 50 PKCE generations per 5 minutes
            RateLimitType.SESSION_CREATION: RateLimitRule(50, 3600, 600), # 50 sessions per hour, block 10 minutes
        }
    
    async def _get_redis(self):
        """Get Redis client with lazy initialization"""
        if self.redis_client is None:
            self.redis_client = await get_redis_client()
        return self.redis_client
    
    def _get_rate_limit_key(
        self, 
        limit_type: RateLimitType, 
        identifier: str, 
        additional_context: str = None
    ) -> str:
        """
        Generate Redis key for rate limiting
        
        Args:
            limit_type: Type of rate limit
            identifier: Primary identifier (IP, user ID, etc.)
            additional_context: Additional context for the key
        """
        context_suffix = f":{additional_context}" if additional_context else ""
        return f"rate_limit:{limit_type.value}:{identifier}{context_suffix}"
    
    def _get_block_key(self, limit_type: RateLimitType, identifier: str) -> str:
        """Generate Redis key for tracking blocked identifiers"""
        return f"rate_limit:blocked:{limit_type.value}:{identifier}"
    
    async def check_rate_limit(
        self,
        limit_type: RateLimitType,
        identifier: str,
        rule: Optional[RateLimitRule] = None,
        additional_context: str = None
    ) -> RateLimitResult:
        """
        Check if request is within rate limits
        
        Args:
            limit_type: Type of rate limit to check
            identifier: Primary identifier (IP address, user ID, etc.)
            rule: Custom rate limit rule (uses default if not provided)
            additional_context: Additional context for more granular limiting
            
        Returns:
            RateLimitResult with allow/deny decision and metadata
        """
        try:
            redis = await self._get_redis()
            rule = rule or self.default_rules.get(limit_type)
            
            if not rule:
                logger.warning(f"No rate limit rule found for {limit_type}")
                return RateLimitResult(allowed=True, remaining=999, reset_time=0)
            
            current_time = int(time.time())
            key = self._get_rate_limit_key(limit_type, identifier, additional_context)
            block_key = self._get_block_key(limit_type, identifier)
            
            # Check if identifier is currently blocked
            block_info = await redis.get(block_key)
            if block_info:
                block_data = json.loads(block_info)
                block_until = block_data.get("block_until", 0)
                
                if current_time < block_until:
                    retry_after = block_until - current_time
                    logger.warning(f"Rate limit blocked: {limit_type.value} for {identifier} (retry in {retry_after}s)")
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=block_until,
                        retry_after=retry_after
                    )
                else:
                    # Block expired, clean up
                    await redis.delete(block_key)
            
            # Use sliding window rate limiting with Redis
            window_start = current_time - rule.window
            
            # Remove old entries and count current requests
            await redis.zremrangebyscore(key, 0, window_start)
            current_requests = await redis.zcard(key)
            
            if current_requests >= rule.requests:
                # Rate limit exceeded, block the identifier
                block_until = current_time + rule.block_duration
                block_data = {
                    "blocked_at": current_time,
                    "block_until": block_until,
                    "limit_type": limit_type.value,
                    "requests": current_requests,
                    "rule": {
                        "requests": rule.requests,
                        "window": rule.window,
                        "block_duration": rule.block_duration
                    }
                }
                
                await redis.setex(block_key, rule.block_duration, json.dumps(block_data))
                
                # Log security event
                await self._log_rate_limit_violation(
                    limit_type, identifier, current_requests, rule, additional_context
                )
                
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=block_until,
                    retry_after=rule.block_duration
                )
            
            # Request is allowed
            remaining = rule.requests - current_requests - 1
            reset_time = current_time + rule.window
            
            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                reset_time=reset_time
            )
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {str(e)}")
            # Fail open - allow request if rate limiting is down
            return RateLimitResult(allowed=True, remaining=999, reset_time=0)
    
    async def record_request(
        self,
        limit_type: RateLimitType,
        identifier: str,
        additional_context: str = None,
        metadata: Dict[str, Any] = None
    ) -> None:
        """
        Record a request for rate limiting tracking
        
        Args:
            limit_type: Type of rate limit
            identifier: Primary identifier
            additional_context: Additional context
            metadata: Additional metadata to store with the request
        """
        try:
            redis = await self._get_redis()
            current_time = int(time.time())
            key = self._get_rate_limit_key(limit_type, identifier, additional_context)
            
            # Add current request to sorted set with score as timestamp
            request_data = {
                "timestamp": current_time,
                "metadata": metadata or {}
            }
            
            await redis.zadd(key, {json.dumps(request_data): current_time})
            
            # Set expiration on the key
            rule = self.default_rules.get(limit_type)
            if rule:
                await redis.expire(key, rule.window + rule.block_duration)
            
            logger.debug(f"Recorded request: {limit_type.value} for {identifier}")
            
        except Exception as e:
            logger.error(f"Failed to record request: {str(e)}")
    
    async def get_rate_limit_status(
        self,
        limit_type: RateLimitType,
        identifier: str,
        additional_context: str = None
    ) -> Dict[str, Any]:
        """
        Get current rate limit status for an identifier
        
        Args:
            limit_type: Type of rate limit
            identifier: Primary identifier
            additional_context: Additional context
            
        Returns:
            Dictionary with rate limit status information
        """
        try:
            redis = await self._get_redis()
            rule = self.default_rules.get(limit_type)
            
            if not rule:
                return {"error": f"No rule found for {limit_type}"}
            
            current_time = int(time.time())
            key = self._get_rate_limit_key(limit_type, identifier, additional_context)
            block_key = self._get_block_key(limit_type, identifier)
            
            # Check if blocked
            is_blocked = False
            block_until = None
            block_info = await redis.get(block_key)
            if block_info:
                block_data = json.loads(block_info)
                block_until = block_data.get("block_until", 0)
                is_blocked = current_time < block_until
            
            # Count current requests in window
            window_start = current_time - rule.window
            await redis.zremrangebyscore(key, 0, window_start)
            current_requests = await redis.zcard(key)
            
            # Get request history
            request_history = []
            requests = await redis.zrange(key, 0, -1, withscores=True)
            for request_data, timestamp in requests:
                try:
                    data = json.loads(request_data)
                    request_history.append({
                        "timestamp": int(timestamp),
                        "datetime": datetime.fromtimestamp(timestamp).isoformat(),
                        "metadata": data.get("metadata", {})
                    })
                except:
                    continue
            
            return {
                "limit_type": limit_type.value,
                "identifier": identifier,
                "rule": {
                    "requests": rule.requests,
                    "window_seconds": rule.window,
                    "block_duration_seconds": rule.block_duration
                },
                "current_requests": current_requests,
                "remaining_requests": max(0, rule.requests - current_requests),
                "is_blocked": is_blocked,
                "block_until": block_until,
                "reset_time": current_time + rule.window,
                "request_history": request_history
            }
            
        except Exception as e:
            logger.error(f"Failed to get rate limit status: {str(e)}")
            return {"error": str(e)}
    
    async def reset_rate_limit(
        self,
        limit_type: RateLimitType,
        identifier: str,
        additional_context: str = None
    ) -> bool:
        """
        Reset rate limit for an identifier (admin function)
        
        Args:
            limit_type: Type of rate limit
            identifier: Primary identifier
            additional_context: Additional context
            
        Returns:
            True if reset was successful
        """
        try:
            redis = await self._get_redis()
            
            key = self._get_rate_limit_key(limit_type, identifier, additional_context)
            block_key = self._get_block_key(limit_type, identifier)
            
            # Delete both the rate limit data and block status
            deleted = await redis.delete(key, block_key)
            
            logger.info(f"Reset rate limit for {limit_type.value}:{identifier} (deleted {deleted} keys)")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Failed to reset rate limit: {str(e)}")
            return False
    
    async def _log_rate_limit_violation(
        self,
        limit_type: RateLimitType,
        identifier: str,
        request_count: int,
        rule: RateLimitRule,
        additional_context: str = None
    ) -> None:
        """Log rate limit violation for security monitoring"""
        try:
            redis = await self._get_redis()
            
            violation_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "limit_type": limit_type.value,
                "identifier": identifier,
                "additional_context": additional_context,
                "request_count": request_count,
                "rule_requests": rule.requests,
                "rule_window": rule.window,
                "block_duration": rule.block_duration,
                "severity": "HIGH" if limit_type in [
                    RateLimitType.LOGIN_ATTEMPT, 
                    RateLimitType.PASSWORD_RESET
                ] else "MEDIUM"
            }
            
            # Store violation log
            log_key = f"security:rate_limit_violations:{int(time.time())}"
            await redis.setex(log_key, 86400 * 7, json.dumps(violation_data))  # Keep for 7 days
            
            # Add to violations index for querying
            violations_index = "security:rate_limit_violations_index"
            await redis.zadd(violations_index, {log_key: time.time()})
            await redis.expire(violations_index, 86400 * 30)  # Keep index for 30 days
            
            logger.warning(
                f"Rate limit violation: {limit_type.value} from {identifier} "
                f"({request_count}/{rule.requests} in {rule.window}s)"
            )
            
        except Exception as e:
            logger.error(f"Failed to log rate limit violation: {str(e)}")
    
    async def get_recent_violations(
        self,
        hours: int = 24,
        limit_type: Optional[RateLimitType] = None
    ) -> List[Dict[str, Any]]:
        """
        Get recent rate limit violations for security monitoring
        
        Args:
            hours: Number of hours to look back
            limit_type: Optional filter by limit type
            
        Returns:
            List of violation records
        """
        try:
            redis = await self._get_redis()
            
            since_timestamp = time.time() - (hours * 3600)
            violations_index = "security:rate_limit_violations_index"
            
            # Get violation keys from the specified time range
            violation_keys = await redis.zrangebyscore(
                violations_index, since_timestamp, time.time()
            )
            
            violations = []
            for key in violation_keys:
                try:
                    violation_data = await redis.get(key.decode() if isinstance(key, bytes) else key)
                    if violation_data:
                        violation = json.loads(violation_data)
                        
                        # Filter by limit type if specified
                        if limit_type and violation.get("limit_type") != limit_type.value:
                            continue
                        
                        violations.append(violation)
                except Exception as e:
                    logger.error(f"Error processing violation key {key}: {str(e)}")
                    continue
            
            # Sort by timestamp (newest first)
            violations.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return violations
            
        except Exception as e:
            logger.error(f"Failed to get recent violations: {str(e)}")
            return []
    
    async def cleanup_expired_data(self) -> Dict[str, int]:
        """
        Clean up expired rate limiting data
        
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            redis = await self._get_redis()
            current_time = int(time.time())
            
            cleaned_keys = 0
            cleaned_violations = 0
            
            # Clean up rate limit keys
            pattern = "rate_limit:*"
            async for key in redis.scan_iter(match=pattern):
                ttl = await redis.ttl(key)
                if ttl == -1:  # Key has no expiration
                    # Check if it's old data that should be cleaned
                    key_parts = key.decode().split(":")
                    if len(key_parts) >= 3:
                        limit_type_str = key_parts[2]
                        if limit_type_str in [lt.value for lt in RateLimitType]:
                            try:
                                limit_type = RateLimitType(limit_type_str)
                                rule = self.default_rules.get(limit_type)
                                if rule:
                                    await redis.expire(key, rule.window + rule.block_duration)
                                    cleaned_keys += 1
                            except:
                                continue
            
            # Clean up old violation logs (older than 30 days)
            old_violations = await redis.zrangebyscore(
                "security:rate_limit_violations_index", 
                0, 
                current_time - (30 * 86400)
            )
            
            for key in old_violations:
                await redis.delete(key)
                cleaned_violations += 1
            
            # Remove old entries from violations index
            await redis.zremrangebyscore(
                "security:rate_limit_violations_index",
                0,
                current_time - (30 * 86400)
            )
            
            logger.info(f"Rate limiting cleanup: {cleaned_keys} keys, {cleaned_violations} violations")
            
            return {
                "cleaned_keys": cleaned_keys,
                "cleaned_violations": cleaned_violations,
                "timestamp": current_time
            }
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired data: {str(e)}")
            return {"error": str(e)}

# Global rate limiting service instance
rate_limiting_service = RateLimitingService()

async def get_rate_limiting_service() -> RateLimitingService:
    """Get rate limiting service instance"""
    return rate_limiting_service