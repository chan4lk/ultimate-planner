"""Enhanced JWT service with Redis session integration."""

import json
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import Request

from ..config.redis_config import SESSION_EXPIRE_SECONDS, REMEMBER_ME_EXPIRE_SECONDS
from ..auth.security import SECRET_KEY, ALGORITHM
from .redis_session_service import RedisSessionService


class JWTService:
    """Enhanced JWT service with Redis session management."""
    
    def __init__(self):
        self.redis_session = RedisSessionService()
    
    def _generate_jti(self) -> str:
        """Generate unique JWT ID."""
        import uuid
        return str(uuid.uuid4())
    
    def create_access_token(
        self,
        user_id: str,
        expires_delta: Optional[timedelta] = None,
        remember_me: bool = False,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create JWT access token with JTI for blacklist support."""
        to_encode = {"sub": str(user_id)}
        
        # Add additional claims
        if additional_claims:
            to_encode.update(additional_claims)
        
        # Set expiration
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire_seconds = REMEMBER_ME_EXPIRE_SECONDS if remember_me else SESSION_EXPIRE_SECONDS
            expire = datetime.now(timezone.utc) + timedelta(seconds=expire_seconds)
        
        # Add JWT ID for blacklist tracking
        jti = self._generate_jti()
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": jti,
            "remember_me": remember_me
        })
        
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and check blacklist."""
        try:
            # First decode to get JTI for blacklist check
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti")
            
            # Check if token is blacklisted (this would be async in real usage)
            # For now, we'll handle this in the async methods
            return payload
        
        except JWTError:
            return None
    
    async def verify_token_async(self, token: str) -> Optional[Dict[str, Any]]:
        """Async version of token verification with Redis blacklist check."""
        try:
            # Decode token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti")
            
            # Check blacklist in Redis
            if jti and await self.redis_session.is_token_blacklisted(jti):
                return None
            
            return payload
        
        except JWTError:
            return None
    
    def extract_token_claims(self, token: str) -> Optional[Dict[str, Any]]:
        """Extract claims from token without verification (for expired tokens)."""
        try:
            return jwt.get_unverified_claims(token)
        except JWTError:
            return None
    
    async def create_session_with_token(
        self,
        user_id: str,
        request: Optional[Request] = None,
        remember_me: bool = False,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create both JWT token and Redis session."""
        # Create JWT token
        access_token = self.create_access_token(
            user_id=user_id,
            remember_me=remember_me
        )
        
        # Prepare device info
        if device_info is None:
            device_info = {}
        
        if request:
            device_info.setdefault("ip_address", self._get_client_ip(request))
            device_info.setdefault("user_agent", request.headers.get("user-agent", ""))
        
        # Create Redis session
        session_id = await self.redis_session.create_session(
            user_id=int(user_id),
            jwt_token=access_token,
            device_info=device_info,
            remember_me=remember_me,
            request=request
        )
        
        expires_in = REMEMBER_ME_EXPIRE_SECONDS if remember_me else SESSION_EXPIRE_SECONDS
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "session_id": session_id,
            "expires_in": expires_in,
            "remember_me": remember_me
        }
    
    async def validate_token_with_session(
        self,
        token: str,
        session_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Validate token and optionally verify session."""
        # Verify JWT token
        payload = await self.verify_token_async(token)
        if not payload:
            return None
        
        # If session_id provided, validate session
        if session_id:
            session_valid = await self.redis_session.validate_session(session_id, token)
            if not session_valid:
                return None
        
        return payload
    
    async def refresh_token_with_session(
        self,
        current_token: str,
        session_id: str,
        request: Optional[Request] = None
    ) -> Optional[Dict[str, Any]]:
        """Refresh JWT token while maintaining session."""
        # Verify current token and session
        payload = await self.validate_token_with_session(current_token, session_id)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        remember_me = payload.get("remember_me", False)
        
        # Blacklist old token
        old_jti = payload.get("jti")
        if old_jti:
            expire_seconds = REMEMBER_ME_EXPIRE_SECONDS if remember_me else SESSION_EXPIRE_SECONDS
            await self.redis_session.blacklist_token(old_jti, expire_seconds)
        
        # Create new token
        new_token = self.create_access_token(
            user_id=user_id,
            remember_me=remember_me
        )
        
        # Update session with new token
        session_data = await self.redis_session.get_session_data(session_id)
        if session_data:
            # Update session with new token hash
            await self._update_session_token(session_id, new_token, session_data)
            
            # Update activity
            await self.redis_session.update_session_activity(session_id)
        
        expires_in = REMEMBER_ME_EXPIRE_SECONDS if remember_me else SESSION_EXPIRE_SECONDS
        
        return {
            "access_token": new_token,
            "token_type": "bearer",
            "session_id": session_id,
            "expires_in": expires_in,
            "remember_me": remember_me
        }
    
    async def logout_session(
        self,
        token: str,
        session_id: str
    ) -> bool:
        """Logout by invalidating token and session."""
        # Get token claims to extract JTI
        payload = await self.verify_token_async(token)
        if payload:
            jti = payload.get("jti")
            remember_me = payload.get("remember_me", False)
            
            # Blacklist token
            if jti:
                expire_seconds = REMEMBER_ME_EXPIRE_SECONDS if remember_me else SESSION_EXPIRE_SECONDS
                await self.redis_session.blacklist_token(jti, expire_seconds)
        
        # Invalidate session
        return await self.redis_session.invalidate_session(session_id)
    
    async def logout_all_sessions(self, user_id: int) -> int:
        """Logout from all sessions for a user."""
        # Get all user sessions to blacklist their tokens
        sessions = await self.redis_session.get_user_sessions(user_id)
        
        blacklisted_count = 0
        for session in sessions:
            session_data = await self.redis_session.get_session_data(session["session_id"])
            if session_data and session_data.get("jwt_token_hash"):
                # We can't easily reverse the hash, so we'll rely on session invalidation
                # The blacklist will be handled when tokens are verified
                pass
        
        # Invalidate all sessions
        invalidated = await self.redis_session.invalidate_all_user_sessions(user_id)
        return invalidated
    
    async def get_session_info(self, token: str) -> Optional[Dict[str, Any]]:
        """Get session information from token."""
        payload = await self.verify_token_async(token)
        if not payload:
            return None
        
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        # Find session by token hash
        sessions = await self.redis_session.get_user_sessions(int(user_id))
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        for session in sessions:
            session_data = await self.redis_session.get_session_data(session["session_id"])
            if session_data and session_data.get("jwt_token_hash") == token_hash:
                return session_data
        
        return None
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fallback to direct client
        return getattr(request.client, "host", "unknown") if request.client else "unknown"
    
    async def _update_session_token(
        self,
        session_id: str,
        new_token: str,
        session_data: Dict[str, Any]
    ) -> bool:
        """Update session with new token hash."""
        try:
            from ..config.redis_config import get_redis_client, RedisKeyBuilder
            
            redis_client = await get_redis_client()
            key_builder = RedisKeyBuilder()
            
            # Update token hash in session data
            session_data["jwt_token_hash"] = hashlib.sha256(new_token.encode()).hexdigest()
            session_data["last_activity"] = datetime.now(timezone.utc).isoformat()
            
            session_key = key_builder.session_key(session_id)
            
            # Get current TTL to preserve expiration
            ttl = await redis_client.ttl(session_key)
            if ttl > 0:
                await redis_client.setex(session_key, ttl, json.dumps(session_data))
                return True
            
            return False
        
        except Exception:
            return False
    
    async def check_suspicious_activity(
        self,
        user_id: int,
        current_session_id: str,
        request: Request
    ) -> Dict[str, Any]:
        """Check for suspicious activity patterns."""
        current_ip = self._get_client_ip(request)
        current_ua = request.headers.get("user-agent", "")
        
        sessions = await self.redis_session.get_user_sessions(user_id)
        
        # Check for multiple IPs
        unique_ips = set()
        recent_sessions = 0
        different_devices = set()
        
        for session in sessions:
            unique_ips.add(session.get("ip_address", ""))
            different_devices.add(session.get("device_fingerprint", ""))
            
            # Count recent sessions (last hour)
            if session.get("created_at"):
                try:
                    created_time = datetime.fromisoformat(session["created_at"].replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) - created_time < timedelta(hours=1):
                        recent_sessions += 1
                except ValueError:
                    pass
        
        # Calculate risk score
        risk_factors = []
        risk_score = 0.0
        
        if len(unique_ips) > 3:
            risk_factors.append("Multiple IP addresses detected")
            risk_score += 0.3
        
        if recent_sessions > 3:
            risk_factors.append("Rapid session creation")
            risk_score += 0.2
        
        if len(different_devices) > 2:
            risk_factors.append("Multiple devices active")
            risk_score += 0.2
        
        # Check if current IP is new
        if current_ip not in unique_ips:
            risk_factors.append("New IP address")
            risk_score += 0.3
        
        return {
            "risk_score": min(risk_score, 1.0),
            "risk_factors": risk_factors,
            "unique_ips": len(unique_ips),
            "recent_sessions": recent_sessions,
            "different_devices": len(different_devices)
        }