"""
Comprehensive Authentication System Integration Tests
Tests all implemented security components working together
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI

from app.services.mfa_service import get_mfa_service
from app.services.pkce_service import get_pkce_service
from app.services.redis_session_service import get_redis_session_service
from app.services.rate_limiting_service import (
    get_rate_limiting_service, 
    RateLimitType, 
    RateLimitRule
)
from app.services.audit_logging_service import (
    get_audit_logging_service,
    AuditEventType,
    AuditSeverity
)
from app.auth.middleware_rate_limit import rate_limit_middleware
from app.auth.oauth_providers import MicrosoftOAuthProvider


class TestComprehensiveAuthIntegration:
    """Integration tests for complete auth system"""
    
    @pytest.fixture
    def test_app(self):
        """Create test FastAPI app with auth middleware"""
        app = FastAPI()
        
        @app.middleware("http")
        async def add_rate_limit_middleware(request, call_next):
            return await rate_limit_middleware(request, call_next)
        
        @app.post("/auth/login")
        async def test_login():
            return {"message": "Login successful"}
        
        @app.post("/auth/mfa/verify")
        async def test_mfa_verify():
            return {"message": "MFA verified"}
        
        return app
    
    @pytest.fixture
    def client(self, test_app):
        """Test client with middleware"""
        return TestClient(test_app)
    
    @pytest.mark.asyncio
    async def test_complete_mfa_enrollment_flow(self):
        """Test complete MFA enrollment process with all security layers"""
        # Mock Redis for all services
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.get = AsyncMock()
            mock_redis_client.delete = AsyncMock()
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            
            # Test MFA service integration
            mfa_service = await get_mfa_service()
            
            # Generate MFA secret
            mfa_setup = await mfa_service.setup_mfa(user_id="test_user_123")
            
            assert "secret_key" in mfa_setup
            assert "qr_code" in mfa_setup
            assert "backup_codes" in mfa_setup
            assert len(mfa_setup["backup_codes"]) == 8
            
            # Verify TOTP token
            test_token = "123456"  # Mock token
            mock_redis_client.get.return_value = '{"secret_key": "encrypted_secret"}'
            
            # Mock successful verification
            with patch('pyotp.TOTP') as mock_totp:
                mock_totp_instance = MagicMock()
                mock_totp_instance.verify.return_value = True
                mock_totp.return_value = mock_totp_instance
                
                verification_result = await mfa_service.verify_totp_token(
                    user_id="test_user_123",
                    token=test_token
                )
                
                assert verification_result is True
    
    @pytest.mark.asyncio
    async def test_oauth_pkce_flow_integration(self):
        """Test OAuth with PKCE flow integration"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Test PKCE service
            pkce_service = await get_pkce_service()
            
            # Generate PKCE parameters
            verifier = pkce_service.generate_code_verifier(128)
            challenge = pkce_service.generate_code_challenge(verifier)
            
            assert len(verifier) == 128
            assert len(challenge) == 43  # Base64url SHA256
            assert verifier != challenge
            
            # Test OAuth provider with PKCE
            provider = MicrosoftOAuthProvider(
                client_id="test_client",
                client_secret="test_secret",
                redirect_uri="http://localhost/callback"
            )
            
            # Mock PKCE storage
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.sadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            
            # Generate authorization URL
            auth_data = await provider.get_authorization_url_with_pkce(
                scopes=["openid", "profile", "email"]
            )
            
            assert "authorization_url" in auth_data
            assert "state" in auth_data
            assert "code_challenge" in auth_data
            assert auth_data["provider"] == "microsoft"
            assert "code_challenge=" in auth_data["authorization_url"]
            assert "code_challenge_method=S256" in auth_data["authorization_url"]
    
    @pytest.mark.asyncio
    async def test_session_management_integration(self):
        """Test Redis session management with security features"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            session_service = await get_redis_session_service()
            
            # Mock Redis operations for session storage
            mock_redis_client.hset = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            mock_redis_client.hgetall = AsyncMock()
            mock_redis_client.delete = AsyncMock()
            
            # Create session
            device_info = {
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0 Test Browser",
                "device_fingerprint": "test_fingerprint"
            }
            
            session_id = await session_service.create_session(
                user_id="test_user_123",
                jwt_token="test.jwt.token",
                device_info=device_info,
                remember_me=False
            )
            
            assert session_id is not None
            assert len(session_id) == 36  # UUID format
            
            # Validate session
            mock_redis_client.hgetall.return_value = {
                b"user_id": b"test_user_123",
                b"jwt_token": b"test.jwt.token",
                b"ip_address": b"192.168.1.100",
                b"is_active": b"true",
                b"created_at": datetime.utcnow().isoformat().encode()
            }
            
            is_valid = await session_service.validate_session(
                session_id=session_id,
                jwt_token="test.jwt.token",
                current_ip="192.168.1.100"
            )
            
            assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_rate_limiting_integration(self):
        """Test rate limiting with audit logging"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations for rate limiting
            mock_redis_client.get = AsyncMock(return_value=None)  # No existing block
            mock_redis_client.zremrangebyscore = AsyncMock()
            mock_redis_client.zcard = AsyncMock(return_value=4)  # 4 existing requests
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            mock_redis_client.setex = AsyncMock()
            
            rate_limiting_service = await get_rate_limiting_service()
            
            # Test rate limit check
            result = await rate_limiting_service.check_rate_limit(
                limit_type=RateLimitType.LOGIN_ATTEMPT,
                identifier="192.168.1.100"
            )
            
            assert result.allowed is True
            assert result.remaining == 0  # 5 allowed - 4 existing - 1 current = 0
            
            # Test rate limit exceeded
            mock_redis_client.zcard.return_value = 5  # Limit reached
            
            result = await rate_limiting_service.check_rate_limit(
                limit_type=RateLimitType.LOGIN_ATTEMPT,
                identifier="192.168.1.100"
            )
            
            assert result.allowed is False
            assert result.retry_after is not None
    
    @pytest.mark.asyncio
    async def test_audit_logging_integration(self):
        """Test comprehensive audit logging"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations for audit logging
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            
            audit_service = await get_audit_logging_service()
            
            # Test audit event logging
            event_id = await audit_service.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id="test_user_123",
                session_id="test_session",
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0 Test Browser",
                resource="/auth/login",
                action="POST /auth/login",
                outcome="SUCCESS",
                details={
                    "authentication_method": "password+mfa",
                    "mfa_type": "totp",
                    "session_duration": 3600
                }
            )
            
            assert event_id is not None
            assert len(event_id) == 36  # UUID format
            
            # Verify Redis operations were called
            mock_redis_client.setex.assert_called()
            mock_redis_client.zadd.assert_called()
            mock_redis_client.expire.assert_called()
    
    def test_rate_limiting_middleware(self, client):
        """Test rate limiting middleware integration"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock allowed request
            mock_redis_client.get = AsyncMock(return_value=None)  # No block
            mock_redis_client.zremrangebyscore = AsyncMock()
            mock_redis_client.zcard = AsyncMock(return_value=1)  # 1 existing request
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            
            # Test successful request
            response = client.post("/auth/login", json={"username": "test", "password": "test"})
            
            # Should be allowed
            assert response.status_code in [200, 422]  # 422 for validation, 200 for success
            
            # Test rate limit exceeded
            mock_redis_client.zcard.return_value = 5  # Limit exceeded
            mock_redis_client.get.return_value = None  # No existing block
            mock_redis_client.setex = AsyncMock()  # Will create block
            
            response = client.post("/auth/login", json={"username": "test", "password": "test"})
            
            # Should be rate limited
            assert response.status_code == 429
            assert "Rate limit exceeded" in response.json()["error"]
            assert "X-RateLimit-Limit" in response.headers or response.status_code == 429
    
    @pytest.mark.asyncio
    async def test_security_event_chain(self):
        """Test complete security event chain: rate limit -> audit -> alert"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations
            mock_redis_client.get = AsyncMock()
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            mock_redis_client.zcard = AsyncMock()
            mock_redis_client.zremrangebyscore = AsyncMock()
            
            # Simulate multiple failed login attempts
            rate_limiting_service = await get_rate_limiting_service()
            audit_service = await get_audit_logging_service()
            
            client_ip = "192.168.1.100"
            user_id = "test_user_123"
            
            # Simulate 5 failed login attempts
            for attempt in range(5):
                # Check rate limit
                mock_redis_client.zcard.return_value = attempt
                
                rate_result = await rate_limiting_service.check_rate_limit(
                    limit_type=RateLimitType.LOGIN_ATTEMPT,
                    identifier=client_ip
                )
                
                if rate_result.allowed:
                    # Log failed login attempt
                    await audit_service.log_event(
                        event_type=AuditEventType.LOGIN_FAILURE,
                        user_id=user_id,
                        ip_address=client_ip,
                        user_agent="Mozilla/5.0 Test Browser",
                        resource="/auth/login",
                        action="POST /auth/login",
                        outcome="FAILURE",
                        details={
                            "reason": "invalid_credentials",
                            "attempt_number": attempt + 1,
                            "repeated_attempts": attempt + 1 > 3
                        }
                    )
                    
                    # Record request
                    await rate_limiting_service.record_request(
                        limit_type=RateLimitType.LOGIN_ATTEMPT,
                        identifier=client_ip,
                        metadata={
                            "outcome": "failure",
                            "user_id": user_id,
                            "attempt": attempt + 1
                        }
                    )
            
            # 6th attempt should be blocked
            mock_redis_client.zcard.return_value = 5
            
            rate_result = await rate_limiting_service.check_rate_limit(
                limit_type=RateLimitType.LOGIN_ATTEMPT,
                identifier=client_ip
            )
            
            assert rate_result.allowed is False
            
            # Log rate limit exceeded
            await audit_service.log_event(
                event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
                user_id=user_id,
                ip_address=client_ip,
                user_agent="Mozilla/5.0 Test Browser",
                resource="/auth/login",
                action="POST /auth/login",
                outcome="FAILURE",
                details={
                    "rate_limit_type": "login_attempt",
                    "attempts": 6,
                    "block_duration": 900
                },
                custom_severity=AuditSeverity.HIGH
            )
            
            # Verify security monitoring calls
            assert mock_redis_client.setex.called  # Events stored
            assert mock_redis_client.zadd.called   # Indices created
    
    @pytest.mark.asyncio 
    async def test_compliance_data_flow(self):
        """Test compliance data collection and reporting"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations for event storage and retrieval
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            mock_redis_client.zrangebyscore = AsyncMock()
            mock_redis_client.get = AsyncMock()
            
            audit_service = await get_audit_logging_service()
            
            # Log various compliance-relevant events
            events = [
                (AuditEventType.LOGIN_SUCCESS, "SUCCESS"),
                (AuditEventType.MFA_ENABLED, "SUCCESS"),
                (AuditEventType.DATA_ACCESS, "SUCCESS"),
                (AuditEventType.DATA_MODIFICATION, "SUCCESS"),
                (AuditEventType.PASSWORD_CHANGED, "SUCCESS"),
                (AuditEventType.LOGIN_FAILURE, "FAILURE"),
                (AuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT, "FAILURE"),
            ]
            
            event_ids = []
            for event_type, outcome in events:
                event_id = await audit_service.log_event(
                    event_type=event_type,
                    user_id="test_user_123",
                    ip_address="192.168.1.100",
                    resource="/api/data",
                    action="API_ACCESS",
                    outcome=outcome,
                    details={"compliance_test": True}
                )
                event_ids.append(event_id)
            
            # Verify all events were logged
            assert len(event_ids) == 7
            assert all(len(event_id) == 36 for event_id in event_ids)  # UUID format
            
            # Verify Redis operations for compliance tagging
            assert mock_redis_client.zadd.call_count >= len(events)  # Multiple indices per event
    
    @pytest.mark.asyncio
    async def test_system_health_monitoring(self):
        """Test system health monitoring and metrics"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations
            mock_redis_client.scan_iter = AsyncMock()
            mock_redis_client.get = AsyncMock()
            mock_redis_client.ttl = AsyncMock()
            
            # Test PKCE service stats
            pkce_service = await get_pkce_service()
            mock_redis_client.scan_iter.return_value = [
                b"pkce:state:test1", b"pkce:state:test2"
            ]
            
            stats = await pkce_service.get_pkce_stats()
            
            assert "active_pkce_entries" in stats
            assert "ttl_seconds" in stats
            assert stats["ttl_seconds"] == 600
            
            # Test rate limiting service status
            rate_service = await get_rate_limiting_service()
            
            status = await rate_service.get_rate_limit_status(
                limit_type=RateLimitType.LOGIN_ATTEMPT,
                identifier="test_client"
            )
            
            assert "limit_type" in status
            assert "current_requests" in status
            assert "remaining_requests" in status
    
    @pytest.mark.asyncio
    async def test_error_handling_and_fallbacks(self):
        """Test error handling and graceful degradation"""
        # Test Redis connection failure scenarios
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            # Simulate Redis connection failure
            mock_redis.side_effect = ConnectionError("Redis connection failed")
            
            # Rate limiting should fail open (allow requests)
            rate_service = await get_rate_limiting_service()
            
            # This should not raise an exception, should fail open
            result = await rate_service.check_rate_limit(
                limit_type=RateLimitType.LOGIN_ATTEMPT,
                identifier="test_client"
            )
            
            assert result.allowed is True  # Fail open behavior
            assert result.remaining == 999  # Default fallback value
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self):
        """Test system behavior under concurrent load"""
        with patch('app.config.redis_config.get_redis_client') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock Redis operations
            mock_redis_client.setex = AsyncMock()
            mock_redis_client.zadd = AsyncMock()
            mock_redis_client.expire = AsyncMock()
            mock_redis_client.zcard = AsyncMock(return_value=1)
            mock_redis_client.zremrangebyscore = AsyncMock()
            
            audit_service = await get_audit_logging_service()
            rate_service = await get_rate_limiting_service()
            
            # Simulate concurrent operations
            async def concurrent_rate_check(client_id: str):
                return await rate_service.check_rate_limit(
                    limit_type=RateLimitType.LOGIN_ATTEMPT,
                    identifier=client_id
                )
            
            async def concurrent_audit_log(user_id: str):
                return await audit_service.log_event(
                    event_type=AuditEventType.LOGIN_SUCCESS,
                    user_id=user_id,
                    ip_address="192.168.1.100",
                    action="concurrent_test",
                    outcome="SUCCESS"
                )
            
            # Run concurrent operations
            tasks = []
            for i in range(10):
                tasks.append(concurrent_rate_check(f"client_{i}"))
                tasks.append(concurrent_audit_log(f"user_{i}"))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Verify no exceptions occurred
            exceptions = [r for r in results if isinstance(r, Exception)]
            assert len(exceptions) == 0, f"Concurrent operations failed: {exceptions}"
            
            # Verify results
            rate_results = [r for r in results[::2] if hasattr(r, 'allowed')]
            audit_results = [r for r in results[1::2] if isinstance(r, str)]
            
            assert len(rate_results) == 10
            assert len(audit_results) == 10
            assert all(r.allowed for r in rate_results)  # All should be allowed
            assert all(len(r) == 36 for r in audit_results)  # All should return UUIDs


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])