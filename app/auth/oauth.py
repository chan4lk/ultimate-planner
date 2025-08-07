"""
OAuth integration framework for external platform authentication.
"""
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode, parse_qs, urlparse
import secrets
import httpx
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from sqlalchemy import select

from .security import encrypt_sensitive_data, decrypt_sensitive_data
from ..models.user_integration import UserIntegration, SyncStatus


class OAuthProvider(str, Enum):
    """Supported OAuth providers."""
    MICROSOFT = "microsoft"
    NOTION = "notion"
    GOOGLE = "google"  # For future use


class OAuthConfig(BaseModel):
    """OAuth provider configuration."""
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    scopes: List[str]
    redirect_uri: str


class OAuthUrl(BaseModel):
    """OAuth authorization URL response."""
    url: HttpUrl
    state: str


class AuthToken(BaseModel):
    """OAuth token response."""
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: Optional[int] = None
    token_type: str = "Bearer"
    scope: Optional[str] = None


class AuthResult(BaseModel):
    """Authentication result."""
    success: bool
    token: Optional[AuthToken] = None
    error: Optional[str] = None
    user_integration_id: Optional[str] = None


class SyncResult(BaseModel):
    """Synchronization result."""
    success: bool
    tasks_synced: int = 0
    error: Optional[str] = None
    last_sync_at: Optional[datetime] = None


class OAuthProviderBase(ABC):
    """Abstract base class for OAuth providers."""
    
    def __init__(self, config: OAuthConfig):
        self.config = config
    
    @abstractmethod
    async def get_authorization_url(self, state: str) -> str:
        """Generate authorization URL for OAuth flow."""
        pass
    
    @abstractmethod
    async def exchange_code_for_token(self, code: str, state: str) -> AuthToken:
        """Exchange authorization code for access token."""
        pass
    
    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> AuthToken:
        """Refresh access token using refresh token."""
        pass
    
    @abstractmethod
    async def revoke_token(self, token: str) -> bool:
        """Revoke access token."""
        pass
    
    @abstractmethod
    async def get_user_info(self, token: str) -> Dict[str, Any]:
        """Get user information from the provider."""
        pass


class MicrosoftOAuthProvider(OAuthProviderBase):
    """Microsoft OAuth provider implementation."""
    
    async def get_authorization_url(self, state: str) -> str:
        """Generate Microsoft OAuth authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(self.config.scopes),
            "state": state,
            "response_mode": "query"
        }
        return f"{self.config.authorization_url}?{urlencode(params)}"
    
    async def exchange_code_for_token(self, code: str, state: str) -> AuthToken:
        """Exchange authorization code for Microsoft access token."""
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.config.redirect_uri
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            token_data = response.json()
        
        return AuthToken(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_in=token_data.get("expires_in"),
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope")
        )
    
    async def refresh_access_token(self, refresh_token: str) -> AuthToken:
        """Refresh Microsoft access token."""
        data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            token_data = response.json()
        
        return AuthToken(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            expires_in=token_data.get("expires_in"),
            token_type=token_data.get("token_type", "Bearer"),
            scope=token_data.get("scope")
        )
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke Microsoft access token."""
        # Microsoft doesn't have a standard revoke endpoint
        # Token expiration handles this automatically
        return True
    
    async def get_user_info(self, token: str) -> Dict[str, Any]:
        """Get user information from Microsoft Graph."""
        headers = {"Authorization": f"Bearer {token}"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers
            )
            response.raise_for_status()
            return response.json()


class NotionOAuthProvider(OAuthProviderBase):
    """Notion OAuth provider implementation."""
    
    async def get_authorization_url(self, state: str) -> str:
        """Generate Notion OAuth authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "state": state
        }
        return f"{self.config.authorization_url}?{urlencode(params)}"
    
    async def exchange_code_for_token(self, code: str, state: str) -> AuthToken:
        """Exchange authorization code for Notion access token."""
        import base64
        
        # Notion requires Basic auth with client credentials
        credentials = base64.b64encode(
            f"{self.config.client_id}:{self.config.client_secret}".encode()
        ).decode()
        
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri
        }
        
        headers = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.token_url,
                json=data,
                headers=headers
            )
            response.raise_for_status()
            token_data = response.json()
        
        return AuthToken(
            access_token=token_data["access_token"],
            token_type=token_data.get("token_type", "Bearer")
        )
    
    async def refresh_access_token(self, refresh_token: str) -> AuthToken:
        """Notion tokens don't expire, so no refresh needed."""
        raise NotImplementedError("Notion tokens do not expire")
    
    async def revoke_token(self, token: str) -> bool:
        """Notion doesn't have a revoke endpoint."""
        return True
    
    async def get_user_info(self, token: str) -> Dict[str, Any]:
        """Get user information from Notion."""
        headers = {
            "Authorization": f"Bearer {token}",
            "Notion-Version": "2022-06-28"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.notion.com/v1/users/me",
                headers=headers
            )
            response.raise_for_status()
            return response.json()


class OAuthManager:
    """Central OAuth management class."""
    
    def __init__(self, db: Session):
        self.db = db
        self._providers: Dict[OAuthProvider, OAuthProviderBase] = {}
        self._state_store: Dict[str, Dict[str, Any]] = {}  # In production, use Redis
    
    def register_provider(self, provider: OAuthProvider, config: OAuthConfig) -> None:
        """Register an OAuth provider with configuration."""
        if provider == OAuthProvider.MICROSOFT:
            self._providers[provider] = MicrosoftOAuthProvider(config)
        elif provider == OAuthProvider.NOTION:
            self._providers[provider] = NotionOAuthProvider(config)
        else:
            raise ValueError(f"Unsupported OAuth provider: {provider}")
    
    def get_provider(self, provider: OAuthProvider) -> OAuthProviderBase:
        """Get OAuth provider instance."""
        if provider not in self._providers:
            raise ValueError(f"Provider {provider} not registered")
        return self._providers[provider]
    
    async def initiate_oauth_flow(self, user_id: str, provider: OAuthProvider) -> OAuthUrl:
        """Initiate OAuth flow for a user and provider."""
        oauth_provider = self.get_provider(provider)
        
        # Generate secure state parameter
        state = secrets.token_urlsafe(32)
        
        # Store state with user and provider info
        self._state_store[state] = {
            "user_id": user_id,
            "provider": provider.value,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)
        }
        
        # Generate authorization URL
        auth_url = await oauth_provider.get_authorization_url(state)
        
        return OAuthUrl(url=auth_url, state=state)
    
    async def handle_oauth_callback(
        self, 
        provider: OAuthProvider, 
        code: str, 
        state: str
    ) -> AuthResult:
        """Handle OAuth callback and complete authentication."""
        # Validate state parameter
        if state not in self._state_store:
            return AuthResult(success=False, error="Invalid or expired state parameter")
        
        state_data = self._state_store[state]
        
        # Check if state is expired
        if datetime.now(timezone.utc) > state_data["expires_at"]:
            del self._state_store[state]
            return AuthResult(success=False, error="State parameter expired")
        
        # Verify provider matches
        if state_data["provider"] != provider.value:
            del self._state_store[state]
            return AuthResult(success=False, error="Provider mismatch")
        
        user_id = state_data["user_id"]
        
        try:
            # Exchange code for token
            oauth_provider = self.get_provider(provider)
            token = await oauth_provider.exchange_code_for_token(code, state)
            
            # Get user info from provider
            user_info = await oauth_provider.get_user_info(token.access_token)
            
            # Store or update user integration
            integration = await self._store_user_integration(
                user_id, provider, token, user_info
            )
            
            # Clean up state
            del self._state_store[state]
            
            return AuthResult(
                success=True,
                token=token,
                user_integration_id=integration.id
            )
            
        except Exception as e:
            # Clean up state on error
            if state in self._state_store:
                del self._state_store[state]
            
            return AuthResult(
                success=False,
                error=f"Authentication failed: {str(e)}"
            )
    
    async def refresh_token(self, user_id: str, provider: OAuthProvider) -> AuthResult:
        """Refresh access token for a user integration."""
        # Get user integration
        integration = self.db.execute(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.source == provider.value
            )
        ).scalar_one_or_none()
        
        if not integration or not integration.refresh_token:
            return AuthResult(success=False, error="No refresh token available")
        
        try:
            oauth_provider = self.get_provider(provider)
            decrypted_refresh_token = decrypt_sensitive_data(integration.refresh_token)
            
            # Refresh the token
            new_token = await oauth_provider.refresh_access_token(decrypted_refresh_token)
            
            # Update stored token
            integration.auth_token = encrypt_sensitive_data(new_token.access_token)
            if new_token.refresh_token:
                integration.refresh_token = encrypt_sensitive_data(new_token.refresh_token)
            
            if new_token.expires_in:
                integration.token_expires_at = (
                    datetime.now(timezone.utc) + timedelta(seconds=new_token.expires_in)
                )
            
            integration.sync_status = SyncStatus.ACTIVE.value
            self.db.commit()
            
            return AuthResult(
                success=True,
                token=new_token,
                user_integration_id=integration.id
            )
            
        except Exception as e:
            # Mark integration as having an error
            integration.sync_status = SyncStatus.ERROR.value
            self.db.commit()
            
            return AuthResult(
                success=False,
                error=f"Token refresh failed: {str(e)}"
            )
    
    async def revoke_access(self, user_id: str, provider: OAuthProvider) -> bool:
        """Revoke access for a user integration."""
        # Get user integration
        integration = self.db.execute(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.source == provider.value
            )
        ).scalar_one_or_none()
        
        if not integration:
            return False
        
        try:
            # Revoke token with provider
            oauth_provider = self.get_provider(provider)
            decrypted_token = decrypt_sensitive_data(integration.auth_token)
            await oauth_provider.revoke_token(decrypted_token)
            
        except Exception:
            # Continue even if revocation fails
            pass
        
        # Remove integration from database
        self.db.delete(integration)
        self.db.commit()
        
        return True
    
    async def get_valid_token(self, user_id: str, provider: OAuthProvider) -> Optional[str]:
        """Get a valid access token for a user integration, refreshing if necessary."""
        integration = self.db.execute(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.source == provider.value,
                UserIntegration.is_active == True
            )
        ).scalar_one_or_none()
        
        if not integration or not integration.auth_token:
            return None
        
        # Check if token is expired and needs refresh
        if integration.is_token_expired() and integration.refresh_token:
            refresh_result = await self.refresh_token(user_id, provider)
            if not refresh_result.success:
                return None
            return refresh_result.token.access_token
        
        return decrypt_sensitive_data(integration.auth_token)
    
    async def _store_user_integration(
        self,
        user_id: str,
        provider: OAuthProvider,
        token: AuthToken,
        user_info: Dict[str, Any]
    ) -> UserIntegration:
        """Store or update user integration with OAuth token."""
        import uuid
        
        # Check if integration already exists
        existing_integration = self.db.execute(
            select(UserIntegration).where(
                UserIntegration.user_id == user_id,
                UserIntegration.source == provider.value
            )
        ).scalar_one_or_none()
        
        if existing_integration:
            # Update existing integration
            integration = existing_integration
        else:
            # Create new integration
            integration = UserIntegration(
                id=str(uuid.uuid4()),
                user_id=user_id,
                source=provider.value
            )
            self.db.add(integration)
        
        # Update token information
        integration.auth_token = encrypt_sensitive_data(token.access_token)
        if token.refresh_token:
            integration.refresh_token = encrypt_sensitive_data(token.refresh_token)
        
        if token.expires_in:
            integration.token_expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=token.expires_in)
            )
        
        integration.is_active = True
        integration.sync_status = SyncStatus.ACTIVE.value
        
        # Store provider-specific configuration
        integration.configuration = {
            "user_info": user_info,
            "token_type": token.token_type,
            "scope": token.scope
        }
        
        self.db.commit()
        self.db.refresh(integration)
        
        return integration
    
    def cleanup_expired_states(self) -> None:
        """Clean up expired state parameters."""
        current_time = datetime.now(timezone.utc)
        expired_states = [
            state for state, data in self._state_store.items()
            if current_time > data["expires_at"]
        ]
        
        for state in expired_states:
            del self._state_store[state]