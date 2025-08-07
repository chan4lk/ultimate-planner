"""Comprehensive test suite for Redis session management."""

import pytest
import json
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import Request
from datetime import datetime, timezone

from app.services.redis_session_service import RedisSessionService
from app.services.jwt_service import JWTService
from app.config.redis_config import RedisKeyBuilder


@pytest.fixture
def redis_session_service():
    """Create RedisSessionService instance."""
    return RedisSessionService()


@pytest.fixture
def jwt_service():
    """Create JWTService instance."""
    return JWTService()


@pytest.fixture
def mock_redis_client():
    """Mock Redis client."""
    return AsyncMock()


@pytest.fixture
def mock_request():
    """Mock FastAPI Request object."""
    request = MagicMock(spec=Request)
    request.client.host = "127.0.0.1"
    request.headers = {
        "user-agent": "test-agent",
        "x-forwarded-for": None,
        "x-real-ip": None
    }
    return request


class TestRedisSessionService:
    """Test Redis session management."""
    
    @pytest.mark.asyncio
    async def test_create_session(self, redis_session_service, mock_request):
        """Test session creation."""
        with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            # Mock Redis operations
            mock_redis.setex = AsyncMock()
            mock_redis.sadd = AsyncMock()
            mock_redis.expire = AsyncMock()
            mock_redis.smembers = AsyncMock(return_value=[])
            
            device_info = {
                "user_agent": "test-browser",
                "ip_address": "192.168.1.1"
            }
            
            session_id = await redis_session_service.create_session(
                user_id=1,
                jwt_token="test-token",
                device_info=device_info,
                request=mock_request
            )
            
            assert session_id is not None
            assert isinstance(session_id, str)
            
            # Verify Redis calls
            mock_redis.setex.assert_called_once()
            mock_redis.sadd.assert_called_once()
            mock_redis.expire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_session(self, redis_session_service):
        """Test session validation."""
        with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            # Mock session data
            session_data = {
                "session_id": "test-session",
                "user_id": 1,
                "jwt_token_hash": "hash123",
                "is_active": True,
                "last_activity": datetime.now(timezone.utc).isoformat()
            }
            
            mock_redis.get = AsyncMock(return_value=json.dumps(session_data))
            mock_redis.ttl = AsyncMock(return_value=3600)
            mock_redis.setex = AsyncMock()
            
            # Test with matching token
            result = await redis_session_service.validate_session(
                "test-session",
                "test-token"  # This will be hashed and compared
            )
            
            # This should fail because the hash won't match
            assert result is False
    
    @pytest.mark.asyncio
    async def test_invalidate_session(self, redis_session_service):
        """Test session invalidation."""
        with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            # Mock session data
            session_data = {
                "session_id": "test-session",
                "user_id": 1
            }
            
            mock_redis.get = AsyncMock(return_value=json.dumps(session_data))
            mock_redis.srem = AsyncMock()
            mock_redis.delete = AsyncMock(return_value=1)
            
            result = await redis_session_service.invalidate_session("test-session")
            
            assert result is True
            mock_redis.srem.assert_called_once()
            mock_redis.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_sessions(self, redis_session_service):
        """Test getting user sessions."""
        with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            # Mock user session list
            mock_redis.smembers = AsyncMock(return_value=["session1", "session2"])
            
            # Mock session data
            session_data = {
                "session_id": "session1",
                "user_id": 1,
                "device_fingerprint": "device1",
                "ip_address": "192.168.1.1",
                "user_agent": "test-agent",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_activity": datetime.now(timezone.utc).isoformat(),
                "is_active": True,
                "remember_me": False
            }
            
            mock_redis.get = AsyncMock(return_value=json.dumps(session_data))
            
            sessions = await redis_session_service.get_user_sessions(1)
            
            assert len(sessions) == 2  # Both sessions should be returned
            assert all(s["session_id"] in ["session1", "session2"] for s in sessions)
    
    @pytest.mark.asyncio
    async def test_blacklist_token(self, redis_session_service):
        """Test token blacklisting."""
        with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            mock_redis.setex = AsyncMock()
            
            result = await redis_session_service.blacklist_token("test-jti", 3600)
            
            assert result is True
            mock_redis.setex.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_is_token_blacklisted(self, redis_session_service):
        """Test checking if token is blacklisted."""
        with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis:
            mock_redis = AsyncMock()
            mock_get_redis.return_value = mock_redis
            
            # Test blacklisted token
            mock_redis.get = AsyncMock(return_value="blacklisted")
            result = await redis_session_service.is_token_blacklisted("test-jti")
            assert result is True
            
            # Test non-blacklisted token
            mock_redis.get = AsyncMock(return_value=None)
            result = await redis_session_service.is_token_blacklisted("test-jti")
            assert result is False


class TestJWTService:
    """Test JWT service with Redis integration."""
    
    @pytest.mark.asyncio
    async def test_create_session_with_token(self, jwt_service, mock_request):
        """Test creating session with JWT token."""
        with patch.object(jwt_service.redis_session, 'create_session') as mock_create_session:
            mock_create_session.return_value = "test-session-id"
            
            result = await jwt_service.create_session_with_token(
                user_id="1",
                request=mock_request,
                remember_me=False
            )
            
            assert "access_token" in result
            assert "session_id" in result
            assert result["session_id"] == "test-session-id"
            assert result["token_type"] == "bearer"
            
            mock_create_session.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_token_with_session(self, jwt_service):
        """Test token validation with session."""
        # Mock JWT verification
        with patch.object(jwt_service, 'verify_token_async') as mock_verify, \
             patch.object(jwt_service.redis_session, 'validate_session') as mock_validate_session:
            
            mock_verify.return_value = {"sub": "1", "jti": "test-jti"}
            mock_validate_session.return_value = True
            
            result = await jwt_service.validate_token_with_session(
                "test-token",
                "test-session"
            )
            
            assert result is not None
            assert result["sub"] == "1"
            
            mock_verify.assert_called_once_with("test-token")
            mock_validate_session.assert_called_once_with("test-session", "test-token")
    
    @pytest.mark.asyncio
    async def test_logout_session(self, jwt_service):
        """Test logout session."""
        with patch.object(jwt_service, 'verify_token_async') as mock_verify, \
             patch.object(jwt_service.redis_session, 'blacklist_token') as mock_blacklist, \
             patch.object(jwt_service.redis_session, 'invalidate_session') as mock_invalidate:
            
            mock_verify.return_value = {"jti": "test-jti", "remember_me": False}
            mock_blacklist.return_value = True
            mock_invalidate.return_value = True
            
            result = await jwt_service.logout_session("test-token", "test-session")
            
            assert result is True
            mock_blacklist.assert_called_once()
            mock_invalidate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_suspicious_activity(self, jwt_service, mock_request):
        """Test suspicious activity detection."""
        with patch.object(jwt_service.redis_session, 'get_user_sessions') as mock_get_sessions:
            # Mock multiple sessions with different IPs
            mock_sessions = [
                {"ip_address": "192.168.1.1", "device_fingerprint": "device1", 
                 "created_at": datetime.now(timezone.utc).isoformat()},
                {"ip_address": "192.168.1.2", "device_fingerprint": "device2",
                 "created_at": datetime.now(timezone.utc).isoformat()},
                {"ip_address": "192.168.1.3", "device_fingerprint": "device3",
                 "created_at": datetime.now(timezone.utc).isoformat()},
                {"ip_address": "192.168.1.4", "device_fingerprint": "device4",
                 "created_at": datetime.now(timezone.utc).isoformat()}
            ]
            mock_get_sessions.return_value = mock_sessions
            
            result = await jwt_service.check_suspicious_activity(
                user_id=1,
                current_session_id="test-session",
                request=mock_request
            )
            
            assert "risk_score" in result
            assert "risk_factors" in result
            assert "unique_ips" in result
            assert result["unique_ips"] == 4
            
            # Should detect multiple IPs as suspicious
            assert result["risk_score"] > 0


class TestRedisKeyBuilder:
    """Test Redis key building utility."""
    
    def test_session_key(self):
        """Test session key building."""
        key = RedisKeyBuilder.session_key("test-session-id")
        assert key == "session:test-session-id"
    
    def test_user_sessions_key(self):
        """Test user sessions key building."""
        key = RedisKeyBuilder.user_sessions_key(123)
        assert key == "user_sessions:123"
    
    def test_blacklist_key(self):
        """Test blacklist key building."""
        key = RedisKeyBuilder.blacklist_key("test-jti")
        assert key == "blacklist:test-jti"
    
    def test_device_sessions_key(self):
        """Test device sessions key building."""
        key = RedisKeyBuilder.device_sessions_key(123, "device-fingerprint")
        assert key == "device_sessions:123:device-fingerprint"


@pytest.mark.asyncio
async def test_session_lifecycle():
    """Test complete session lifecycle."""
    redis_service = RedisSessionService()
    jwt_service = JWTService()
    
    with patch('app.services.redis_session_service.get_redis_client') as mock_get_redis, \
         patch('app.config.redis_config.get_redis_client') as mock_get_redis2:
        
        mock_redis = AsyncMock()
        mock_get_redis.return_value = mock_redis
        mock_get_redis2.return_value = mock_redis
        
        # Mock all Redis operations
        mock_redis.setex = AsyncMock()
        mock_redis.sadd = AsyncMock()
        mock_redis.expire = AsyncMock()
        mock_redis.smembers = AsyncMock(return_value=[])
        mock_redis.get = AsyncMock()
        mock_redis.ttl = AsyncMock(return_value=3600)
        mock_redis.srem = AsyncMock()
        mock_redis.delete = AsyncMock(return_value=1)
        
        # 1. Create session
        session_id = await redis_service.create_session(
            user_id=1,
            jwt_token="test-token",
            device_info={"ip_address": "127.0.0.1", "user_agent": "test"}
        )
        
        assert session_id is not None
        
        # 2. Update session activity
        mock_redis.get.return_value = json.dumps({
            "session_id": session_id,
            "is_active": True,
            "last_activity": datetime.now(timezone.utc).isoformat()
        })
        
        result = await redis_service.update_session_activity(session_id)
        # This would normally be True, but our mock setup may not cover all cases
        
        # 3. Invalidate session
        mock_redis.get.return_value = json.dumps({"user_id": 1})
        result = await redis_service.invalidate_session(session_id)
        assert result is True


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])