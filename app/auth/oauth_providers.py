"""
Enhanced OAuth Providers with PKCE Support for OAuth 2.1 Compliance
"""

import uuid
from typing import Dict, Any, Optional
from urllib.parse import urlencode
import httpx

from app.services.pkce_service import get_pkce_service
from app.config.redis_config import get_redis_client
from app.core.logging import get_logger

logger = get_logger(__name__)

class PKCEOAuthProvider:
    """Base OAuth provider with PKCE support"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.provider_name = self.__class__.__name__.lower().replace('oauthprovider', '')
    
    async def get_authorization_url_with_pkce(
        self, 
        scopes: list[str] = None,
        user_session: str = None
    ) -> Dict[str, Any]:
        """
        Generate OAuth authorization URL with PKCE parameters
        
        Returns:
            Dictionary containing authorization URL and PKCE data
        """
        try:
            pkce_service = await get_pkce_service()
            
            # Generate PKCE parameters
            code_verifier = pkce_service.generate_code_verifier()
            code_challenge = pkce_service.generate_code_challenge(code_verifier)
            state = str(uuid.uuid4())
            
            # Store PKCE data in Redis
            await pkce_service.store_pkce_data(
                state=state,
                verifier=code_verifier,
                challenge=code_challenge,
                method="S256",
                provider=self.provider_name,
                user_session=user_session
            )
            
            # Build authorization URL
            auth_params = {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256"
            }
            
            if scopes:
                auth_params["scope"] = " ".join(scopes)
            
            # Add provider-specific parameters
            auth_params.update(self._get_provider_specific_params())
            
            authorization_url = f"{self.get_authorization_endpoint()}?{urlencode(auth_params)}"
            
            logger.info(f"Generated PKCE authorization URL for {self.provider_name}")
            
            return {
                "authorization_url": authorization_url,
                "state": state,
                "code_challenge": code_challenge,
                "provider": self.provider_name
            }
            
        except Exception as e:
            logger.error(f"Failed to generate PKCE authorization URL: {str(e)}")
            raise
    
    async def exchange_code_with_pkce(
        self,
        authorization_code: str,
        state: str
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for tokens using PKCE
        
        Args:
            authorization_code: Authorization code from callback
            state: State parameter from callback
            
        Returns:
            Token response from OAuth provider
        """
        try:
            pkce_service = await get_pkce_service()
            
            # Retrieve and validate PKCE data
            pkce_data = await pkce_service.retrieve_pkce_data(state)
            if not pkce_data:
                raise ValueError("Invalid or expired PKCE state")
            
            # Validate PKCE
            code_verifier = pkce_data["verifier"]
            if not await pkce_service.validate_pkce(state, code_verifier, self.provider_name):
                raise ValueError("PKCE validation failed")
            
            # Prepare token exchange request
            token_data = {
                "client_id": self.client_id,
                "grant_type": "authorization_code",
                "code": authorization_code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": code_verifier
            }
            
            # Add client secret for confidential clients
            if self.client_secret:
                token_data["client_secret"] = self.client_secret
            
            # Make token request
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.get_token_endpoint(),
                    data=token_data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json"
                    }
                )
                
                if response.status_code != 200:
                    logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
                    raise ValueError(f"Token exchange failed: {response.status_code}")
                
                token_response = response.json()
                
            logger.info(f"Successfully exchanged code for tokens using PKCE ({self.provider_name})")
            
            return token_response
            
        except Exception as e:
            logger.error(f"PKCE token exchange failed: {str(e)}")
            raise
    
    def _get_provider_specific_params(self) -> Dict[str, str]:
        """Override in subclasses for provider-specific parameters"""
        return {}
    
    def get_authorization_endpoint(self) -> str:
        """Override in subclasses"""
        raise NotImplementedError
    
    def get_token_endpoint(self) -> str:
        """Override in subclasses"""
        raise NotImplementedError


class MicrosoftOAuthProvider(PKCEOAuthProvider):
    """Microsoft Graph OAuth provider with PKCE support"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str, tenant: str = "common"):
        super().__init__(client_id, client_secret, redirect_uri)
        self.tenant = tenant
        self.provider_name = "microsoft"
    
    def get_authorization_endpoint(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/authorize"
    
    def get_token_endpoint(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"
    
    def _get_provider_specific_params(self) -> Dict[str, str]:
        return {
            "response_mode": "query"
        }
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Microsoft Graph"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://graph.microsoft.com/v1.0/me",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json"
                    }
                )
                
                if response.status_code != 200:
                    raise ValueError(f"Failed to get user info: {response.status_code}")
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Failed to get Microsoft user info: {str(e)}")
            raise


class NotionOAuthProvider(PKCEOAuthProvider):
    """Notion OAuth provider with PKCE support"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.provider_name = "notion"
    
    def get_authorization_endpoint(self) -> str:
        return "https://api.notion.com/v1/oauth/authorize"
    
    def get_token_endpoint(self) -> str:
        return "https://api.notion.com/v1/oauth/token"
    
    def _get_provider_specific_params(self) -> Dict[str, str]:
        return {
            "owner": "user"
        }
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Notion"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.notion.com/v1/users/me",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Notion-Version": "2022-06-28",
                        "Accept": "application/json"
                    }
                )
                
                if response.status_code != 200:
                    raise ValueError(f"Failed to get user info: {response.status_code}")
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Failed to get Notion user info: {str(e)}")
            raise


class GoogleOAuthProvider(PKCEOAuthProvider):
    """Google OAuth provider with PKCE support"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.provider_name = "google"
    
    def get_authorization_endpoint(self) -> str:
        return "https://accounts.google.com/o/oauth2/v2/auth"
    
    def get_token_endpoint(self) -> str:
        return "https://oauth2.googleapis.com/token"
    
    def _get_provider_specific_params(self) -> Dict[str, str]:
        return {
            "access_type": "offline",
            "include_granted_scopes": "true"
        }
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Google"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json"
                    }
                )
                
                if response.status_code != 200:
                    raise ValueError(f"Failed to get user info: {response.status_code}")
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Failed to get Google user info: {str(e)}")
            raise


class GitHubOAuthProvider(PKCEOAuthProvider):
    """GitHub OAuth provider with PKCE support"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        super().__init__(client_id, client_secret, redirect_uri)
        self.provider_name = "github"
    
    def get_authorization_endpoint(self) -> str:
        return "https://github.com/login/oauth/authorize"
    
    def get_token_endpoint(self) -> str:
        return "https://github.com/login/oauth/access_token"
    
    def _get_provider_specific_params(self) -> Dict[str, str]:
        return {}
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from GitHub"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                        "User-Agent": "UltimatePlanner/1.0"
                    }
                )
                
                if response.status_code != 200:
                    raise ValueError(f"Failed to get user info: {response.status_code}")
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Failed to get GitHub user info: {str(e)}")
            raise


# OAuth provider factory
OAUTH_PROVIDERS = {
    "microsoft": MicrosoftOAuthProvider,
    "notion": NotionOAuthProvider,
    "google": GoogleOAuthProvider,
    "github": GitHubOAuthProvider,
}

def create_oauth_provider(
    provider_name: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    **kwargs
) -> PKCEOAuthProvider:
    """
    Factory function to create OAuth provider instances
    
    Args:
        provider_name: Name of the OAuth provider
        client_id: OAuth client ID
        client_secret: OAuth client secret
        redirect_uri: OAuth redirect URI
        **kwargs: Additional provider-specific parameters
    
    Returns:
        OAuth provider instance with PKCE support
    """
    if provider_name not in OAUTH_PROVIDERS:
        raise ValueError(f"Unsupported OAuth provider: {provider_name}")
    
    provider_class = OAUTH_PROVIDERS[provider_name]
    
    if provider_name == "microsoft":
        tenant = kwargs.get("tenant", "common")
        return provider_class(client_id, client_secret, redirect_uri, tenant)
    else:
        return provider_class(client_id, client_secret, redirect_uri)