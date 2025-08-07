"""
Tests for PKCE OAuth 2.1 implementation
"""

import pytest
import uuid
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from httpx import Response

from app.services.pkce_service import PKCEService
from app.auth.oauth_providers import (
    MicrosoftOAuthProvider,
    NotionOAuthProvider,
    GoogleOAuthProvider,
    GitHubOAuthProvider,
    create_oauth_provider
)


class TestPKCEService:
    """Test PKCE service functionality"""
    
    @pytest.fixture
    def pkce_service(self):
        return PKCEService()
    
    def test_generate_code_verifier_default_length(self, pkce_service):
        """Test code verifier generation with default length"""
        verifier = pkce_service.generate_code_verifier()
        assert len(verifier) <= 128
        assert len(verifier) >= 43
        # Should be base64url encoded (no padding)
        assert "=" not in verifier
    
    def test_generate_code_verifier_custom_length(self, pkce_service):
        """Test code verifier generation with custom length"""
        verifier = pkce_service.generate_code_verifier(64)
        assert len(verifier) == 64
        assert "=" not in verifier
    
    def test_generate_code_verifier_invalid_length(self, pkce_service):
        """Test code verifier generation with invalid length"""
        with pytest.raises(ValueError):
            pkce_service.generate_code_verifier(42)  # Too short
        
        with pytest.raises(ValueError):
            pkce_service.generate_code_verifier(129)  # Too long
    
    def test_generate_code_challenge_s256(self, pkce_service):
        """Test code challenge generation with S256 method"""
        verifier = "test_verifier_12345"
        challenge = pkce_service.generate_code_challenge(verifier, "S256")
        
        assert challenge != verifier
        assert len(challenge) == 43  # Base64url encoded SHA256
        assert "=" not in challenge
    
    def test_generate_code_challenge_plain(self, pkce_service):
        """Test code challenge generation with plain method"""
        verifier = "test_verifier_12345"
        challenge = pkce_service.generate_code_challenge(verifier, "plain")
        
        assert challenge == verifier
    
    def test_generate_code_challenge_invalid_method(self, pkce_service):
        """Test code challenge generation with invalid method"""
        verifier = "test_verifier_12345"
        
        with pytest.raises(ValueError):
            pkce_service.generate_code_challenge(verifier, "invalid")
    
    @pytest.mark.asyncio
    async def test_store_and_retrieve_pkce_data(self, pkce_service):
        """Test storing and retrieving PKCE data"""
        with patch.object(pkce_service, '_get_redis') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            state = str(uuid.uuid4())
            verifier = "test_verifier"
            challenge = "test_challenge"
            
            # Test store
            await pkce_service.store_pkce_data(
                state=state,
                verifier=verifier,
                challenge=challenge,
                provider="test"
            )
            
            mock_redis_client.setex.assert_called_once()
            mock_redis_client.sadd.assert_called_once()
            mock_redis_client.expire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_validate_pkce_success(self, pkce_service):
        """Test successful PKCE validation"""
        with patch.object(pkce_service, '_get_redis') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            state = str(uuid.uuid4())
            verifier = pkce_service.generate_code_verifier()
            challenge = pkce_service.generate_code_challenge(verifier)
            
            # Mock retrieve_pkce_data
            pkce_data = {
                "verifier": verifier,
                "challenge": challenge,
                "method": "S256",
                "provider": "test"
            }
            
            with patch.object(pkce_service, 'retrieve_pkce_data', return_value=pkce_data):
                result = await pkce_service.validate_pkce(state, verifier, "test")
                assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_pkce_failure(self, pkce_service):
        """Test PKCE validation failure"""
        with patch.object(pkce_service, '_get_redis'):
            state = str(uuid.uuid4())
            wrong_verifier = "wrong_verifier"
            
            # Mock retrieve_pkce_data returns None (expired/not found)
            with patch.object(pkce_service, 'retrieve_pkce_data', return_value=None):
                result = await pkce_service.validate_pkce(state, wrong_verifier, "test")
                assert result is False
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_pkce(self, pkce_service):
        """Test cleanup of expired PKCE data"""
        with patch.object(pkce_service, '_get_redis') as mock_redis:
            mock_redis_client = AsyncMock()
            mock_redis.return_value = mock_redis_client
            
            # Mock scan_iter to return cleanup keys
            mock_redis_client.scan_iter.return_value = [
                b"pkce:cleanup:1000000000",  # Old timestamp
                b"pkce:cleanup:9999999999"   # Future timestamp
            ]
            
            # Mock smembers to return states
            mock_redis_client.smembers.return_value = [b"state1", b"state2"]
            mock_redis_client.delete.return_value = 1  # Successfully deleted
            
            result = await pkce_service.cleanup_expired_pkce()
            assert isinstance(result, int)
            assert result >= 0


class TestOAuthProviders:
    """Test OAuth provider implementations"""
    
    def test_microsoft_oauth_provider(self):
        """Test Microsoft OAuth provider initialization"""
        provider = MicrosoftOAuthProvider(
            client_id="test_id",
            client_secret="test_secret", 
            redirect_uri="http://localhost/callback",
            tenant="test_tenant"
        )
        
        assert provider.provider_name == "microsoft"
        assert provider.tenant == "test_tenant"
        assert "test_tenant" in provider.get_authorization_endpoint()
        assert "test_tenant" in provider.get_token_endpoint()
    
    def test_notion_oauth_provider(self):
        """Test Notion OAuth provider initialization"""
        provider = NotionOAuthProvider(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback"
        )
        
        assert provider.provider_name == "notion"
        assert "notion.com" in provider.get_authorization_endpoint()
        assert "notion.com" in provider.get_token_endpoint()
    
    def test_google_oauth_provider(self):
        """Test Google OAuth provider initialization"""
        provider = GoogleOAuthProvider(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback"
        )
        
        assert provider.provider_name == "google"
        assert "accounts.google.com" in provider.get_authorization_endpoint()
        assert "googleapis.com" in provider.get_token_endpoint()
    
    def test_github_oauth_provider(self):
        """Test GitHub OAuth provider initialization"""
        provider = GitHubOAuthProvider(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback"
        )
        
        assert provider.provider_name == "github"
        assert "github.com" in provider.get_authorization_endpoint()
        assert "github.com" in provider.get_token_endpoint()
    
    def test_create_oauth_provider_factory(self):
        """Test OAuth provider factory function"""
        # Test Microsoft with tenant
        provider = create_oauth_provider(
            "microsoft", "client_id", "client_secret", "redirect_uri", tenant="custom"
        )
        assert isinstance(provider, MicrosoftOAuthProvider)
        assert provider.tenant == "custom"
        
        # Test other providers
        for provider_name, provider_class in [
            ("notion", NotionOAuthProvider),
            ("google", GoogleOAuthProvider), 
            ("github", GitHubOAuthProvider)
        ]:
            provider = create_oauth_provider(
                provider_name, "client_id", "client_secret", "redirect_uri"
            )
            assert isinstance(provider, provider_class)
        
        # Test invalid provider
        with pytest.raises(ValueError):
            create_oauth_provider("invalid", "id", "secret", "uri")
    
    @pytest.mark.asyncio
    async def test_get_authorization_url_with_pkce(self):
        """Test authorization URL generation with PKCE"""
        provider = MicrosoftOAuthProvider(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback"
        )
        
        with patch('app.auth.oauth_providers.get_pkce_service') as mock_get_service:
            mock_service = AsyncMock()
            mock_get_service.return_value = mock_service
            
            mock_service.generate_code_verifier.return_value = "test_verifier"
            mock_service.generate_code_challenge.return_value = "test_challenge"
            
            result = await provider.get_authorization_url_with_pkce(
                scopes=["openid", "profile"]
            )
            
            assert "authorization_url" in result
            assert "state" in result
            assert "code_challenge" in result
            assert "provider" in result
            assert result["provider"] == "microsoft"
            
            # Verify PKCE parameters are in URL
            url = result["authorization_url"]
            assert "code_challenge=test_challenge" in url
            assert "code_challenge_method=S256" in url
    
    @pytest.mark.asyncio
    async def test_exchange_code_with_pkce(self):
        """Test token exchange with PKCE validation"""
        provider = MicrosoftOAuthProvider(
            client_id="test_id",
            client_secret="test_secret",
            redirect_uri="http://localhost/callback"
        )
        
        with patch('app.auth.oauth_providers.get_pkce_service') as mock_get_service:
            mock_service = AsyncMock()
            mock_get_service.return_value = mock_service
            
            # Mock PKCE validation
            pkce_data = {
                "verifier": "test_verifier",
                "challenge": "test_challenge",
                "method": "S256",
                "provider": "microsoft"
            }
            mock_service.retrieve_pkce_data.return_value = pkce_data
            mock_service.validate_pkce.return_value = True
            
            # Mock HTTP response
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "access_token": "test_token",
                "token_type": "Bearer",
                "expires_in": 3600
            }
            
            with patch('httpx.AsyncClient') as mock_client:
                mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                    return_value=mock_response
                )
                
                result = await provider.exchange_code_with_pkce(
                    authorization_code="test_code",
                    state="test_state"
                )
                
                assert result["access_token"] == "test_token"
                assert result["token_type"] == "Bearer"
                assert result["expires_in"] == 3600


class TestOAuthRouter:
    """Test OAuth router endpoints"""
    
    @pytest.fixture
    def client(self):
        from app.main import app
        return TestClient(app)
    
    @pytest.fixture
    def mock_oauth_config(self):
        """Mock OAuth configuration"""
        config = {
            "microsoft": {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "tenant": "common",
                "scopes": ["openid", "profile", "email"]
            }
        }
        
        with patch('app.auth.router_oauth_pkce.OAUTH_CONFIG', config):
            yield config
    
    def test_list_oauth_providers(self, client):
        """Test listing OAuth providers"""
        response = client.get("/oauth/providers")
        assert response.status_code == 200
        
        data = response.json()
        assert "providers" in data
        assert "total_configured" in data
        assert data["pkce_enabled"] is True
        assert data["oauth_version"] == "2.1"
    
    def test_oauth_health_check(self, client):
        """Test OAuth health check endpoint"""
        response = client.get("/oauth/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert data["oauth_version"] == "2.1"
        assert data["pkce_enabled"] is True
    
    def test_get_authorization_url_invalid_provider(self, client):
        """Test authorization URL with invalid provider"""
        response = client.get("/oauth/invalid_provider/authorize")
        assert response.status_code == 400
        assert "Unsupported OAuth provider" in response.json()["detail"]
    
    def test_pkce_stats_endpoint(self, client):
        """Test PKCE statistics endpoint"""
        with patch('app.auth.router_oauth_pkce.get_pkce_service') as mock_service:
            mock_service_instance = AsyncMock()
            mock_service.return_value = mock_service_instance
            mock_service_instance.get_pkce_stats.return_value = {
                "active_pkce_entries": 5,
                "cleanup_batches": 2,
                "ttl_seconds": 600,
                "timestamp": "2023-01-01T00:00:00"
            }
            
            response = client.get("/oauth/pkce/stats")
            assert response.status_code == 200
            
            data = response.json()
            assert data["active_pkce_entries"] == 5
            assert data["cleanup_batches"] == 2
            assert data["ttl_seconds"] == 600
    
    def test_pkce_cleanup_endpoint(self, client):
        """Test PKCE cleanup endpoint"""
        with patch('app.auth.router_oauth_pkce.get_pkce_service') as mock_service:
            mock_service_instance = AsyncMock()
            mock_service.return_value = mock_service_instance
            mock_service_instance.cleanup_expired_pkce.return_value = 3
            
            response = client.post("/oauth/pkce/cleanup")
            assert response.status_code == 200
            
            data = response.json()
            assert data["cleaned_entries"] == 3
            assert "Cleaned up 3 expired PKCE entries" in data["message"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])