"""
Rate Limiting Middleware for FastAPI Authentication Endpoints
Integrates with comprehensive rate limiting service
"""

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Callable, Dict, Any
import time

from app.services.rate_limiting_service import (
    get_rate_limiting_service, 
    RateLimitType, 
    RateLimitRule
)
from app.services.audit_logging_service import (
    get_audit_logging_service,
    AuditEventType
)
from app.core.logging import get_logger

logger = get_logger(__name__)

# Rate limiting configuration for different endpoint patterns
ENDPOINT_RATE_LIMITS = {
    "/auth/login": RateLimitType.LOGIN_ATTEMPT,
    "/auth/login-mfa": RateLimitType.LOGIN_ATTEMPT,
    "/auth/complete-mfa": RateLimitType.MFA_VERIFICATION,
    "/auth/mfa/verify": RateLimitType.MFA_VERIFICATION,
    "/auth/mfa/setup": RateLimitType.MFA_VERIFICATION,
    "/auth/register": RateLimitType.REGISTRATION,
    "/auth/password-reset": RateLimitType.PASSWORD_RESET,
    "/auth/sessions/refresh": RateLimitType.TOKEN_REFRESH,
    "/oauth": RateLimitType.OAUTH_AUTHORIZATION,
    "/auth/sessions/enhanced-login": RateLimitType.LOGIN_ATTEMPT,
}

def get_client_identifier(request: Request) -> str:
    """
    Get client identifier for rate limiting (IP address with forwarded IP support)
    
    Args:
        request: FastAPI request object
        
    Returns:
        Client identifier string
    """
    # Check for forwarded IP (behind proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        client_ip = forwarded_for.split(",")[0].strip()
    else:
        # Check for real IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            client_ip = real_ip
        else:
            # Fall back to direct client IP
            client_ip = request.client.host if request.client else "unknown"
    
    return client_ip

def get_rate_limit_type_for_endpoint(path: str, method: str) -> RateLimitType:
    """
    Determine rate limit type based on endpoint path and method
    
    Args:
        path: Request path
        method: HTTP method
        
    Returns:
        Rate limit type for the endpoint
    """
    # Exact path matches
    if path in ENDPOINT_RATE_LIMITS:
        return ENDPOINT_RATE_LIMITS[path]
    
    # Pattern matches
    if path.startswith("/oauth/") and "authorize" in path:
        return RateLimitType.OAUTH_AUTHORIZATION
    
    if path.startswith("/auth/mfa/"):
        return RateLimitType.MFA_VERIFICATION
    
    if path.startswith("/auth/sessions/"):
        return RateLimitType.SESSION_CREATION
    
    # Default for auth endpoints
    if path.startswith("/auth/"):
        return RateLimitType.LOGIN_ATTEMPT
    
    # No rate limiting for other endpoints
    return None

async def rate_limit_middleware(request: Request, call_next: Callable) -> JSONResponse:
    """
    Rate limiting middleware for authentication endpoints
    
    Args:
        request: FastAPI request object
        call_next: Next middleware/endpoint in chain
        
    Returns:
        Response or rate limit error
    """
    start_time = time.time()
    
    try:
        # Determine if rate limiting applies
        rate_limit_type = get_rate_limit_type_for_endpoint(
            request.url.path, 
            request.method
        )
        
        if not rate_limit_type:
            # No rate limiting for this endpoint
            response = await call_next(request)
            return response
        
        # Get client identifier
        client_id = get_client_identifier(request)
        
        # Additional context for granular rate limiting
        user_agent = request.headers.get("User-Agent", "")[:100]  # Truncate to avoid abuse
        additional_context = f"ua:{hash(user_agent) % 1000}"  # Hash user agent for context
        
        # Check rate limit
        rate_limiting_service = await get_rate_limiting_service()
        rate_limit_result = await rate_limiting_service.check_rate_limit(
            limit_type=rate_limit_type,
            identifier=client_id,
            additional_context=additional_context
        )
        
        if not rate_limit_result.allowed:
            # Rate limit exceeded
            audit_service = await get_audit_logging_service()
            
            # Log rate limit violation
            await audit_service.log_event(
                event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
                ip_address=client_id,
                user_agent=user_agent,
                resource=request.url.path,
                action=f"{request.method} {request.url.path}",
                outcome="FAILURE",
                details={
                    "rate_limit_type": rate_limit_type.value,
                    "remaining": rate_limit_result.remaining,
                    "reset_time": rate_limit_result.reset_time,
                    "retry_after": rate_limit_result.retry_after
                }
            )
            
            # Return rate limit error
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Too many {rate_limit_type.value} attempts. Please try again later.",
                    "retry_after": rate_limit_result.retry_after,
                    "reset_time": rate_limit_result.reset_time
                },
                headers={
                    "X-RateLimit-Limit": str(rate_limiting_service.default_rules.get(rate_limit_type, RateLimitRule(0, 0, 0)).requests),
                    "X-RateLimit-Remaining": str(rate_limit_result.remaining),
                    "X-RateLimit-Reset": str(rate_limit_result.reset_time),
                    "Retry-After": str(rate_limit_result.retry_after) if rate_limit_result.retry_after else "300"
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Record successful request for rate limiting tracking
        await rate_limiting_service.record_request(
            limit_type=rate_limit_type,
            identifier=client_id,
            additional_context=additional_context,
            metadata={
                "endpoint": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "processing_time": time.time() - start_time
            }
        )
        
        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(
            rate_limiting_service.default_rules.get(rate_limit_type, RateLimitRule(0, 0, 0)).requests
        )
        response.headers["X-RateLimit-Remaining"] = str(rate_limit_result.remaining)
        response.headers["X-RateLimit-Reset"] = str(rate_limit_result.reset_time)
        
        return response
        
    except Exception as e:
        logger.error(f"Rate limiting middleware error: {str(e)}")
        # On error, allow request to proceed (fail open)
        response = await call_next(request)
        return response

class RateLimitException(HTTPException):
    """Custom exception for rate limiting violations"""
    
    def __init__(
        self, 
        detail: str, 
        retry_after: int, 
        rate_limit_type: str,
        headers: Dict[str, str] = None
    ):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers=headers or {}
        )
        self.retry_after = retry_after
        self.rate_limit_type = rate_limit_type

async def check_endpoint_rate_limit(
    request: Request,
    rate_limit_type: RateLimitType,
    user_id: str = None,
    custom_rule: RateLimitRule = None
) -> None:
    """
    Manual rate limit check for specific endpoints
    
    Args:
        request: FastAPI request object
        rate_limit_type: Type of rate limit to check
        user_id: Optional user ID for user-specific limiting
        custom_rule: Optional custom rate limit rule
        
    Raises:
        RateLimitException: If rate limit is exceeded
    """
    try:
        client_id = get_client_identifier(request)
        
        # Use user ID if available for user-specific limiting
        identifier = user_id if user_id else client_id
        
        rate_limiting_service = await get_rate_limiting_service()
        rate_limit_result = await rate_limiting_service.check_rate_limit(
            limit_type=rate_limit_type,
            identifier=identifier,
            rule=custom_rule
        )
        
        if not rate_limit_result.allowed:
            # Log rate limit violation
            audit_service = await get_audit_logging_service()
            await audit_service.log_event(
                event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
                user_id=user_id,
                ip_address=client_id,
                user_agent=request.headers.get("User-Agent"),
                resource=request.url.path,
                action=f"{request.method} {request.url.path}",
                outcome="FAILURE",
                details={
                    "rate_limit_type": rate_limit_type.value,
                    "identifier_type": "user" if user_id else "ip",
                    "remaining": rate_limit_result.remaining,
                    "retry_after": rate_limit_result.retry_after
                }
            )
            
            raise RateLimitException(
                detail=f"Rate limit exceeded for {rate_limit_type.value}. Please try again later.",
                retry_after=rate_limit_result.retry_after or 300,
                rate_limit_type=rate_limit_type.value,
                headers={
                    "X-RateLimit-Limit": str(rate_limiting_service.default_rules.get(rate_limit_type, RateLimitRule(0, 0, 0)).requests),
                    "X-RateLimit-Remaining": str(rate_limit_result.remaining),
                    "X-RateLimit-Reset": str(rate_limit_result.reset_time),
                    "Retry-After": str(rate_limit_result.retry_after or 300)
                }
            )
        
        # Record request
        await rate_limiting_service.record_request(
            limit_type=rate_limit_type,
            identifier=identifier,
            metadata={
                "endpoint": request.url.path,
                "method": request.method,
                "user_id": user_id,
                "ip_address": client_id
            }
        )
        
    except RateLimitException:
        raise
    except Exception as e:
        logger.error(f"Rate limit check failed: {str(e)}")
        # Fail open - don't block on errors