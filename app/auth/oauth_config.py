"""
OAuth provider configuration management.
"""
import os
from typing import Dict, Optional
from dotenv import load_dotenv

from .oauth import OAuthProvider, OAuthConfig

load_dotenv()


class OAuthConfigManager:
    """Manages OAuth provider configurations."""
    
    def __init__(self):
        self._configs: Dict[OAuthProvider, OAuthConfig] = {}
        self._load_default_configs()
    
    def _load_default_configs(self) -> None:
        """Load default OAuth configurations from environment variables."""
        # Microsoft OAuth configuration
        microsoft_client_id = os.getenv("MICROSOFT_CLIENT_ID")
        microsoft_client_secret = os.getenv("MICROSOFT_CLIENT_SECRET")
        microsoft_redirect_uri = os.getenv("MICROSOFT_REDIRECT_URI", "http://localhost:8000/auth/oauth/microsoft/callback")
        
        if microsoft_client_id and microsoft_client_secret:
            self._configs[OAuthProvider.MICROSOFT] = OAuthConfig(
                client_id=microsoft_client_id,
                client_secret=microsoft_client_secret,
                authorization_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                scopes=[
                    "https://graph.microsoft.com/User.Read",
                    "https://graph.microsoft.com/Tasks.ReadWrite",
                    "https://graph.microsoft.com/Group.Read.All",
                    "https://graph.microsoft.com/ChannelMessage.Read.All"
                ],
                redirect_uri=microsoft_redirect_uri
            )
        
        # Notion OAuth configuration
        notion_client_id = os.getenv("NOTION_CLIENT_ID")
        notion_client_secret = os.getenv("NOTION_CLIENT_SECRET")
        notion_redirect_uri = os.getenv("NOTION_REDIRECT_URI", "http://localhost:8000/auth/oauth/notion/callback")
        
        if notion_client_id and notion_client_secret:
            self._configs[OAuthProvider.NOTION] = OAuthConfig(
                client_id=notion_client_id,
                client_secret=notion_client_secret,
                authorization_url="https://api.notion.com/v1/oauth/authorize",
                token_url="https://api.notion.com/v1/oauth/token",
                scopes=[],  # Notion doesn't use scopes in the same way
                redirect_uri=notion_redirect_uri
            )
        
        # Google OAuth configuration (for future use)
        google_client_id = os.getenv("GOOGLE_CLIENT_ID")
        google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        google_redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/oauth/google/callback")
        
        if google_client_id and google_client_secret:
            self._configs[OAuthProvider.GOOGLE] = OAuthConfig(
                client_id=google_client_id,
                client_secret=google_client_secret,
                authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                scopes=[
                    "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/userinfo.profile",
                    "https://www.googleapis.com/auth/tasks"
                ],
                redirect_uri=google_redirect_uri
            )
    
    def get_config(self, provider: OAuthProvider) -> Optional[OAuthConfig]:
        """Get OAuth configuration for a provider."""
        return self._configs.get(provider)
    
    def set_config(self, provider: OAuthProvider, config: OAuthConfig) -> None:
        """Set OAuth configuration for a provider."""
        self._configs[provider] = config
    
    def is_provider_configured(self, provider: OAuthProvider) -> bool:
        """Check if a provider is configured."""
        return provider in self._configs
    
    def get_configured_providers(self) -> list[OAuthProvider]:
        """Get list of configured providers."""
        return list(self._configs.keys())
    
    def update_config(
        self,
        provider: OAuthProvider,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        scopes: Optional[list[str]] = None
    ) -> None:
        """Update specific fields of a provider configuration."""
        if provider not in self._configs:
            raise ValueError(f"Provider {provider} is not configured")
        
        config = self._configs[provider]
        
        if client_id is not None:
            config.client_id = client_id
        if client_secret is not None:
            config.client_secret = client_secret
        if redirect_uri is not None:
            config.redirect_uri = redirect_uri
        if scopes is not None:
            config.scopes = scopes


# Global configuration manager instance
oauth_config_manager = OAuthConfigManager()


def get_oauth_config_manager() -> OAuthConfigManager:
    """Get the global OAuth configuration manager."""
    return oauth_config_manager