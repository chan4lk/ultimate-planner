"""Redis-based session management service."""

import json
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import Request

from ..config.redis_config import (
    get_redis_client,
    RedisKeyBuilder,
    SESSION_EXPIRE_SECONDS,
    REMEMBER_ME_EXPIRE_SECONDS,
    MAX_SESSIONS_PER_USER
)


class RedisSessionService:
    """Redis-based session management service."""
    
    def __init__(self):
        self.key_builder = RedisKeyBuilder()
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return str(uuid.uuid4())
    
    def _create_device_fingerprint(self, request: Optional[Request], user_agent: str = None) -> str:
        """Create device fingerprint from request data."""
        if request:
            ip = self._get_client_ip(request)
            user_agent = request.headers.get("user-agent", "")
        else:
            ip = "unknown"
            user_agent = user_agent or "unknown"
        
        # Create fingerprint from IP and User-Agent
        fingerprint_data = f"{ip}:{user_agent}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()[:16]
    
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
    
    async def create_session(
        self,
        user_id: int,
        jwt_token: str,
        device_info: Dict[str, Any],
        remember_me: bool = False,
        request: Optional[Request] = None
    ) -> str:
        """Create a new user session."""
        redis_client = await get_redis_client()
        session_id = self._generate_session_id()
        
        # Extract device info
        device_fingerprint = device_info.get(
            "device_fingerprint",
            self._create_device_fingerprint(request, device_info.get("user_agent"))
        )
        
        # Session data
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "jwt_token_hash": hashlib.sha256(jwt_token.encode()).hexdigest(),
            "device_fingerprint": device_fingerprint,
            "ip_address": device_info.get("ip_address", self._get_client_ip(request) if request else "unknown"),
            "user_agent": device_info.get("user_agent", request.headers.get("user-agent", "") if request else ""),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_activity": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
            "remember_me": remember_me
        }
        
        # Set expiration time
        expire_seconds = REMEMBER_ME_EXPIRE_SECONDS if remember_me else SESSION_EXPIRE_SECONDS
        
        # Store session data
        session_key = self.key_builder.session_key(session_id)
        await redis_client.setex(session_key, expire_seconds, json.dumps(session_data))
        
        # Add to user's session list
        user_sessions_key = self.key_builder.user_sessions_key(user_id)
        await redis_client.sadd(user_sessions_key, session_id)
        await redis_client.expire(user_sessions_key, expire_seconds)
        
        # Check session limit and remove oldest if necessary
        await self._enforce_session_limit(user_id)
        
        return session_id
    
    async def validate_session(self, session_id: str, jwt_token: str) -> bool:
        """Validate session and JWT token match."""
        try:
            redis_client = await get_redis_client()
            session_key = self.key_builder.session_key(session_id)
            
            session_data_json = await redis_client.get(session_key)
            if not session_data_json:
                return False
            
            session_data = json.loads(session_data_json)
            
            # Check if session is active
            if not session_data.get("is_active", False):
                return False
            
            # Verify JWT token hash matches
            token_hash = hashlib.sha256(jwt_token.encode()).hexdigest()
            if session_data.get("jwt_token_hash") != token_hash:
                return False
            
            # Update last activity
            session_data["last_activity"] = datetime.now(timezone.utc).isoformat()
            
            # Get current TTL to preserve expiration
            ttl = await redis_client.ttl(session_key)
            if ttl > 0:
                await redis_client.setex(session_key, ttl, json.dumps(session_data))
            
            return True
        
        except (json.JSONDecodeError, KeyError, Exception):
            return False
    
    async def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by session ID."""
        try:
            redis_client = await get_redis_client()
            session_key = self.key_builder.session_key(session_id)
            
            session_data_json = await redis_client.get(session_key)
            if not session_data_json:
                return None
            
            return json.loads(session_data_json)
        
        except (json.JSONDecodeError, Exception):
            return None
    
    async def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a specific session."""
        try:
            redis_client = await get_redis_client()
            
            # Get session data first to remove from user's session list
            session_data = await self.get_session_data(session_id)
            if session_data:
                user_id = session_data.get("user_id")
                if user_id:
                    user_sessions_key = self.key_builder.user_sessions_key(user_id)
                    await redis_client.srem(user_sessions_key, session_id)
            
            # Remove session data
            session_key = self.key_builder.session_key(session_id)
            deleted = await redis_client.delete(session_key)
            
            return deleted > 0
        
        except Exception:
            return False
    
    async def invalidate_all_user_sessions(self, user_id: int) -> int:
        """Invalidate all sessions for a user."""
        try:
            redis_client = await get_redis_client()
            user_sessions_key = self.key_builder.user_sessions_key(user_id)
            
            # Get all session IDs for the user
            session_ids = await redis_client.smembers(user_sessions_key)
            
            if not session_ids:
                return 0
            
            # Delete all sessions
            session_keys = [self.key_builder.session_key(sid) for sid in session_ids]
            deleted = await redis_client.delete(*session_keys)
            
            # Clear user's session list
            await redis_client.delete(user_sessions_key)
            
            return deleted
        
        except Exception:
            return 0
    
    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all active sessions for a user."""
        try:
            redis_client = await get_redis_client()
            user_sessions_key = self.key_builder.user_sessions_key(user_id)
            
            session_ids = await redis_client.smembers(user_sessions_key)
            if not session_ids:
                return []
            
            sessions = []
            for session_id in session_ids:
                session_data = await self.get_session_data(session_id)
                if session_data and session_data.get("is_active", False):
                    # Remove sensitive data
                    clean_session = {
                        "session_id": session_data.get("session_id"),
                        "device_fingerprint": session_data.get("device_fingerprint"),
                        "ip_address": session_data.get("ip_address"),
                        "user_agent": session_data.get("user_agent"),
                        "created_at": session_data.get("created_at"),
                        "last_activity": session_data.get("last_activity"),
                        "remember_me": session_data.get("remember_me", False)
                    }
                    sessions.append(clean_session)
            
            # Sort by last activity (most recent first)
            sessions.sort(key=lambda x: x.get("last_activity", ""), reverse=True)
            return sessions
        
        except Exception:
            return []
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions (Redis TTL handles this automatically, but this cleans up references)."""
        try:
            redis_client = await get_redis_client()
            cleaned = 0
            
            # This is a maintenance operation that would typically run as a background task
            # Redis TTL automatically expires the session data, but we need to clean up
            # user session lists that might reference expired sessions
            
            # Get all user session keys
            user_session_keys = await redis_client.keys(f"{self.key_builder.USER_SESSIONS_KEY_PREFIX}*")
            
            for user_sessions_key in user_session_keys:
                session_ids = await redis_client.smembers(user_sessions_key)
                
                # Check each session ID to see if it still exists
                valid_sessions = []
                for session_id in session_ids:
                    session_key = self.key_builder.session_key(session_id)
                    if await redis_client.exists(session_key):
                        valid_sessions.append(session_id)
                    else:
                        cleaned += 1
                
                # Update the user's session list with only valid sessions
                if valid_sessions:
                    await redis_client.delete(user_sessions_key)
                    await redis_client.sadd(user_sessions_key, *valid_sessions)
                else:
                    await redis_client.delete(user_sessions_key)
            
            return cleaned
        
        except Exception:
            return 0
    
    async def _enforce_session_limit(self, user_id: int) -> None:
        """Enforce maximum sessions per user."""
        try:
            redis_client = await get_redis_client()
            user_sessions_key = self.key_builder.user_sessions_key(user_id)
            
            session_ids = await redis_client.smembers(user_sessions_key)
            
            if len(session_ids) > MAX_SESSIONS_PER_USER:
                # Get session data with timestamps to find oldest
                session_times = []
                for session_id in session_ids:
                    session_data = await self.get_session_data(session_id)
                    if session_data:
                        created_at = session_data.get("created_at", "")
                        session_times.append((session_id, created_at))
                
                # Sort by creation time (oldest first)
                session_times.sort(key=lambda x: x[1])
                
                # Remove oldest sessions
                sessions_to_remove = len(session_ids) - MAX_SESSIONS_PER_USER
                for i in range(sessions_to_remove):
                    session_id_to_remove = session_times[i][0]
                    await self.invalidate_session(session_id_to_remove)
        
        except Exception:
            pass  # Don't fail the login if session cleanup fails
    
    async def blacklist_token(self, token_jti: str, expire_seconds: int = None) -> bool:
        """Add JWT token to blacklist."""
        try:
            redis_client = await get_redis_client()
            blacklist_key = self.key_builder.blacklist_key(token_jti)
            
            # Store token in blacklist with expiration
            expire_time = expire_seconds or SESSION_EXPIRE_SECONDS
            await redis_client.setex(blacklist_key, expire_time, "blacklisted")
            
            return True
        
        except Exception:
            return False
    
    async def is_token_blacklisted(self, token_jti: str) -> bool:
        """Check if JWT token is blacklisted."""
        try:
            redis_client = await get_redis_client()
            blacklist_key = self.key_builder.blacklist_key(token_jti)
            
            result = await redis_client.get(blacklist_key)
            return result is not None
        
        except Exception:
            return False
    
    async def get_session_by_user_and_device(self, user_id: int, device_fingerprint: str) -> Optional[str]:
        """Get existing session for user and device combination."""
        try:
            sessions = await self.get_user_sessions(user_id)
            
            for session in sessions:
                if session.get("device_fingerprint") == device_fingerprint:
                    return session.get("session_id")
            
            return None
        
        except Exception:
            return None
    
    async def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity timestamp."""
        try:
            redis_client = await get_redis_client()
            session_key = self.key_builder.session_key(session_id)
            
            session_data_json = await redis_client.get(session_key)
            if not session_data_json:
                return False
            
            session_data = json.loads(session_data_json)
            session_data["last_activity"] = datetime.now(timezone.utc).isoformat()
            
            # Preserve current TTL
            ttl = await redis_client.ttl(session_key)
            if ttl > 0:
                await redis_client.setex(session_key, ttl, json.dumps(session_data))
                return True
            
            return False
        
        except Exception:
            return False
    
    async def get_redis_health(self) -> Dict[str, Any]:
        """Get Redis connection health status."""
        try:
            redis_client = await get_redis_client()
            info = await redis_client.info()
            
            return {
                "status": "healthy",
                "connected_clients": info.get("connected_clients", 0),
                "used_memory": info.get("used_memory_human", "unknown"),
                "uptime_in_seconds": info.get("uptime_in_seconds", 0),
                "redis_version": info.get("redis_version", "unknown")
            }
        
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }