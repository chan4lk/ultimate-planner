"""
Tests for OAuth integration framework.
"""
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth.oauth import (
    OAuthManager, OAuthProvider, OAuthConfig, OAuthUrl, AuthToken, AuthResult,
    MicrosoftOAuthProvider, NotionOAuthProvider
)
from app.auth.oauth_config import OAuthConfigManager
from app.models.base import Base
from app.models.user_integration import UserIntegration, SyncStatus


# Test database setup
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(TEST_DATABASE_URL)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture
def db_session():
    """Create a test database session."""
    Base.metadata.create_all(bind=test_engine)
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def oauth_config():
    """Create test OAuth configuration."""
    return OAuthConfig(
        client_id="test_client_id",
        client_secret="test_client_secret",
        authorization_url="https://example.com/oauth/authorize",
        token_url="https://example.com/oauth/token",
        scopes=["read", "write"],
        redirect_uri="http://localhost:8000/callback"
    )


@pytest.fixture
def oauth_manager(db_session, oauth_config):
    """Create OAuth manager with test configuration."""
    manager = OAuthManager(db_session)
    manager.register_provider(OAuthProvider.MICROSOFT, oauth_config)
    return manager


class TestOAuthConfig:
    """Test OAuth configuration management."""
    
    def test_oauth_config_creation(self, oauth_config):
        """Test OAuth configuration creation."""
        assert oauth_config.client_id == "test_client_id"
        assert oauth_config.client_secret == "test_client_secret"
        assert oauth_config.authorization_url == "https://example.com/oauth/authorize"
        assert oauth_config.token_url == "https://example.com/oauth/token"
        assert oauth_config.scopes == ["read", "write"]
        assert oauth_config.redirect_uri == "http://localhost:8000/callback"
    
    def test_oauth_config_manager(self):
        """Test OAuth configuration manager."""
        config_manager = OAuthConfigManager()
        
        # Test setting and getting configuration
        test_config = OAuthConfig(
            client_id="test_id",
            client_secret="test_secret",
            authorization_url="https://test.com/auth",
            token_url="https://test.com/token",
            scopes=["test"],
            redirect_uri="http://test.com/callback"
        )
        
        config_manager.set_config(OAuthProvider.MICROSOFT, test_config)
        retrieved_config = config_manager.get_config(OAuthProvider.MICROSOFT)
        
        assert retrieved_config is not None
        assert retrieved_config.client_id == "test_id"
        assert config_manager.is_provider_configured(OAuthProvider.MICROSOFT)
        assert OAuthProvider.MICROSOFT in config_manager.get_configured_providers()


class TestMicrosoftOAuthProvider:
    """Test Microsoft OAuth provider."""
    
    @pytest.mark.asyncio
    async def test_get_authorization_url(self, oauth_config):
        """Test Microsoft authorization URL generation."""
        provider = MicrosoftOAuthProvider(oauth_config)
        state = "test_state"
        
        url = await provider.get_authorization_url(state)
        
        assert "https://example.com/oauth/authorize" in url
        assert "client_id=test_client_id" in url
        assert "response_type=code" in url
        assert "state=test_state" in url
        assert "scope=read+write" in url
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_exchange_code_for_token(self, mock_client_class, oauth_config):
        """Test exchanging authorization code for token."""
        # Mock successful token response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "read write"
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client
        
        provider = MicrosoftOAuthProvider(oauth_config)
        token = await provider.exchange_code_for_token("test_code", "test_state")
        
        assert token.access_token == "test_access_token"
        assert token.refresh_token == "test_refresh_token"
        assert token.expires_in == 3600
        assert token.token_type == "Bearer"
        assert token.scope == "read write"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_refresh_access_token(self, mock_client_class, oauth_config):
        """Test refreshing access token."""
        # Mock successful refresh response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client
        
        provider = MicrosoftOAuthProvider(oauth_config)
        token = await provider.refresh_access_token("old_refresh_token")
        
        assert token.access_token == "new_access_token"
        assert token.refresh_token == "new_refresh_token"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_get_user_info(self, mock_client_class, oauth_config):
        """Test getting user information."""
        # Mock user info response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "user123",
            "displayName": "Test User",
            "mail": "test@example.com"
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client
        
        provider = MicrosoftOAuthProvider(oauth_config)
        user_info = await provider.get_user_info("test_token")
        
        assert user_info["id"] == "user123"
        assert user_info["displayName"] == "Test User"
        assert user_info["mail"] == "test@example.com"


class TestNotionOAuthProvider:
    """Test Notion OAuth provider."""
    
    @pytest.mark.asyncio
    async def test_get_authorization_url(self, oauth_config):
        """Test Notion authorization URL generation."""
        provider = NotionOAuthProvider(oauth_config)
        state = "test_state"
        
        url = await provider.get_authorization_url(state)
        
        assert "https://example.com/oauth/authorize" in url
        assert "client_id=test_client_id" in url
        assert "response_type=code" in url
        assert "state=test_state" in url
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient')
    async def test_exchange_code_for_token(self, mock_client_class, oauth_config):
        """Test exchanging authorization code for token."""
        # Mock successful token response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "token_type": "Bearer"
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value.__aenter__.return_value = mock_client
        
        provider = NotionOAuthProvider(oauth_config)
        token = await provider.exchange_code_for_token("test_code", "test_state")
        
        assert token.access_token == "test_access_token"
        assert token.token_type == "Bearer"
    
    @pytest.mark.asyncio
    async def test_refresh_access_token_not_implemented(self, oauth_config):
        """Test that refresh token is not implemented for Notion."""
        provider = NotionOAuthProvider(oauth_config)
        
        with pytest.raises(NotImplementedError):
            await provider.refresh_access_token("refresh_token")


class TestOAuthManager:
    """Test OAuth manager functionality."""
    
    def test_register_provider(self, oauth_manager):
        """Test provider registration."""
        assert OAuthProvider.MICROSOFT in oauth_manager._providers
        
        provider = oauth_manager.get_provider(OAuthProvider.MICROSOFT)
        assert isinstance(provider, MicrosoftOAuthProvider)
    
    def test_get_unregistered_provider(self, oauth_manager):
        """Test getting unregistered provider raises error."""
        with pytest.raises(ValueError, match="Provider .* not registered"):
            oauth_manager.get_provider(OAuthProvider.NOTION)
    
    @pytest.mark.asyncio
    async def test_initiate_oauth_flow(self, oauth_manager):
        """Test initiating OAuth flow."""
        user_id = "test_user"
        
        oauth_url = await oauth_manager.initiate_oauth_flow(user_id, OAuthProvider.MICROSOFT)
        
        assert isinstance(oauth_url, OAuthUrl)
        assert oauth_url.state is not None
        assert len(oauth_url.state) > 0
        assert "https://example.com/oauth/authorize" in str(oauth_url.url)
        
        # Check that state is stored
        assert oauth_url.state in oauth_manager._state_store
        state_data = oauth_manager._state_store[oauth_url.state]
        assert state_data["user_id"] == user_id
        assert state_data["provider"] == OAuthProvider.MICROSOFT.value
    
    @pytest.mark.asyncio
    @patch('app.auth.oauth.MicrosoftOAuthProvider.exchange_code_for_token')
    @patch('app.auth.oauth.MicrosoftOAuthProvider.get_user_info')
    async def test_handle_oauth_callback_success(
        self, mock_get_user_info, mock_exchange_token, oauth_manager
    ):
        """Test successful OAuth callback handling."""
        # Setup mocks
        mock_token = AuthToken(
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_in=3600,
            token_type="Bearer"
        )
        mock_exchange_token.return_value = mock_token
        mock_get_user_info.return_value = {"id": "user123", "name": "Test User"}
        
        # Initiate OAuth flow first
        user_id = "test_user"
        oauth_url = await oauth_manager.initiate_oauth_flow(user_id, OAuthProvider.MICROSOFT)
        
        # Handle callback
        result = await oauth_manager.handle_oauth_callback(
            OAuthProvider.MICROSOFT, "test_code", oauth_url.state
        )
        
        assert result.success is True
        assert result.token is not None
        assert result.token.access_token == "test_access_token"
        assert result.user_integration_id is not None
        
        # Check that state is cleaned up
        assert oauth_url.state not in oauth_manager._state_store
    
    @pytest.mark.asyncio
    async def test_handle_oauth_callback_invalid_state(self, oauth_manager):
        """Test OAuth callback with invalid state."""
        result = await oauth_manager.handle_oauth_callback(
            OAuthProvider.MICROSOFT, "test_code", "invalid_state"
        )
        
        assert result.success is False
        assert "Invalid or expired state parameter" in result.error
    
    @pytest.mark.asyncio
    async def test_handle_oauth_callback_expired_state(self, oauth_manager):
        """Test OAuth callback with expired state."""
        # Manually add expired state
        expired_state = "expired_state"
        oauth_manager._state_store[expired_state] = {
            "user_id": "test_user",
            "provider": OAuthProvider.MICROSOFT.value,
            "created_at": datetime.now(timezone.utc) - timedelta(minutes=20),
            "expires_at": datetime.now(timezone.utc) - timedelta(minutes=10)
        }
        
        result = await oauth_manager.handle_oauth_callback(
            OAuthProvider.MICROSOFT, "test_code", expired_state
        )
        
        assert result.success is False
        assert "State parameter expired" in result.error
        assert expired_state not in oauth_manager._state_store
    
    @pytest.mark.asyncio
    async def test_handle_oauth_callback_provider_mismatch(self, oauth_manager):
        """Test OAuth callback with provider mismatch."""
        # Initiate flow with Microsoft
        user_id = "test_user"
        oauth_url = await oauth_manager.initiate_oauth_flow(user_id, OAuthProvider.MICROSOFT)
        
        # Try to handle callback with Notion
        result = await oauth_manager.handle_oauth_callback(
            OAuthProvider.NOTION, "test_code", oauth_url.state
        )
        
        assert result.success is False
        assert "Provider mismatch" in result.error
    
    def test_cleanup_expired_states(self, oauth_manager):
        """Test cleanup of expired state parameters."""
        # Add some states with different expiration times
        current_time = datetime.now(timezone.utc)
        
        oauth_manager._state_store["valid_state"] = {
            "user_id": "user1",
            "provider": "microsoft",
            "created_at": current_time,
            "expires_at": current_time + timedelta(minutes=5)
        }
        
        oauth_manager._state_store["expired_state"] = {
            "user_id": "user2",
            "provider": "microsoft",
            "created_at": current_time - timedelta(minutes=20),
            "expires_at": current_time - timedelta(minutes=10)
        }
        
        # Cleanup expired states
        oauth_manager.cleanup_expired_states()
        
        # Check that only valid state remains
        assert "valid_state" in oauth_manager._state_store
        assert "expired_state" not in oauth_manager._state_store
    
    @pytest.mark.asyncio
    async def test_revoke_access(self, oauth_manager, db_session):
        """Test revoking access for a user integration."""
        # Create a test user integration
        integration = UserIntegration(
            id="test_integration",
            user_id="test_user",
            source=OAuthProvider.MICROSOFT.value,
            auth_token="encrypted_token",
            is_active=True,
            sync_status=SyncStatus.ACTIVE.value
        )
        db_session.add(integration)
        db_session.commit()
        
        # Revoke access
        result = await oauth_manager.revoke_access("test_user", OAuthProvider.MICROSOFT)
        
        assert result is True
        
        # Check that integration is removed
        remaining_integration = db_session.query(UserIntegration).filter_by(
            user_id="test_user", source=OAuthProvider.MICROSOFT.value
        ).first()
        assert remaining_integration is None


class TestAuthToken:
    """Test AuthToken model."""
    
    def test_auth_token_creation(self):
        """Test AuthToken creation with all fields."""
        token = AuthToken(
            access_token="test_access_token",
            refresh_token="test_refresh_token",
            expires_in=3600,
            token_type="Bearer",
            scope="read write"
        )
        
        assert token.access_token == "test_access_token"
        assert token.refresh_token == "test_refresh_token"
        assert token.expires_in == 3600
        assert token.token_type == "Bearer"
        assert token.scope == "read write"
    
    def test_auth_token_minimal(self):
        """Test AuthToken creation with minimal fields."""
        token = AuthToken(access_token="test_token")
        
        assert token.access_token == "test_token"
        assert token.refresh_token is None
        assert token.expires_in is None
        assert token.token_type == "Bearer"
        assert token.scope is None


class TestAuthResult:
    """Test AuthResult model."""
    
    def test_auth_result_success(self):
        """Test successful AuthResult."""
        token = AuthToken(access_token="test_token")
        result = AuthResult(
            success=True,
            token=token,
            user_integration_id="integration_123"
        )
        
        assert result.success is True
        assert result.token == token
        assert result.user_integration_id == "integration_123"
        assert result.error is None
    
    def test_auth_result_failure(self):
        """Test failed AuthResult."""
        result = AuthResult(
            success=False,
            error="Authentication failed"
        )
        
        assert result.success is False
        assert result.token is None
        assert result.user_integration_id is None
        assert result.error == "Authentication failed"


if __name__ == "__main__":
    pytest.main([__file__])