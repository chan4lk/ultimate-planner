"""
OAuth Router with PKCE Support for OAuth 2.1 Compliance
Enhanced security with Proof Key for Code Exchange
"""

from fastapi import APIRouter, HTTPException, Query, Request, Depends
from fastapi.responses import RedirectResponse
from typing import Dict, Any, Optional
import os

from app.auth.oauth_providers import create_oauth_provider, OAUTH_PROVIDERS
from app.auth.schemas_pkce import (
    PKCEAuthorizationResponse,
    PKCECallbackRequest,
    PKCETokenResponse,
    PKCEStatsResponse
)
from app.services.pkce_service import get_pkce_service
from app.auth.dependencies import get_current_user_optional
from app.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/oauth", tags=["oauth-pkce"])

# OAuth configuration from environment
OAUTH_CONFIG = {
    "microsoft": {
        "client_id": os.getenv("MICROSOFT_CLIENT_ID"),
        "client_secret": os.getenv("MICROSOFT_CLIENT_SECRET"),
        "tenant": os.getenv("MICROSOFT_TENANT", "common"),
        "scopes": ["openid", "profile", "email", "User.Read"]
    },
    "notion": {
        "client_id": os.getenv("NOTION_CLIENT_ID"), 
        "client_secret": os.getenv("NOTION_CLIENT_SECRET"),
        "scopes": ["read_content", "update_content"]
    },
    "google": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "scopes": ["openid", "profile", "email"]
    },
    "github": {
        "client_id": os.getenv("GITHUB_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
        "scopes": ["user:email", "read:user"]
    }
}

def get_redirect_uri(provider: str, request: Request) -> str:
    """Generate redirect URI for OAuth provider"""
    base_url = str(request.base_url).rstrip('/')
    return f"{base_url}/oauth/{provider}/callback"

def validate_provider(provider: str) -> None:
    """Validate OAuth provider is supported and configured"""
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported OAuth provider: {provider}. Supported: {list(OAUTH_PROVIDERS.keys())}"
        )
    
    config = OAUTH_CONFIG.get(provider)
    if not config or not config.get("client_id") or not config.get("client_secret"):
        raise HTTPException(
            status_code=500,
            detail=f"OAuth provider {provider} is not properly configured"
        )

@router.get("/{provider}/authorize", response_model=PKCEAuthorizationResponse)
async def get_authorization_url(
    provider: str,
    request: Request,
    scopes: Optional[str] = Query(None, description="Space-separated OAuth scopes"),
    current_user = Depends(get_current_user_optional)
):
    """
    Generate OAuth authorization URL with PKCE parameters
    
    - **provider**: OAuth provider name (microsoft, notion, google, github)
    - **scopes**: Optional custom scopes (defaults to provider defaults)
    - **Returns**: Authorization URL with PKCE challenge and state
    """
    try:
        # Validate provider
        validate_provider(provider)
        config = OAUTH_CONFIG[provider]
        
        # Determine scopes
        if scopes:
            scope_list = scopes.split()
        else:
            scope_list = config["scopes"]
        
        # Create OAuth provider with PKCE support
        redirect_uri = get_redirect_uri(provider, request)
        oauth_provider = create_oauth_provider(
            provider_name=provider,
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            redirect_uri=redirect_uri,
            tenant=config.get("tenant")  # Microsoft-specific
        )
        
        # Generate authorization URL with PKCE
        user_session = current_user.id if current_user else None
        auth_data = await oauth_provider.get_authorization_url_with_pkce(
            scopes=scope_list,
            user_session=str(user_session) if user_session else None
        )
        
        logger.info(f"Generated OAuth authorization URL for {provider} (user: {user_session})")
        
        return PKCEAuthorizationResponse(
            authorization_url=auth_data["authorization_url"],
            state=auth_data["state"],
            code_challenge=auth_data["code_challenge"],
            provider=provider,
            scopes=scope_list
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate authorization URL for {provider}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate authorization URL: {str(e)}")

@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    code: str = Query(..., description="Authorization code from OAuth provider"),
    state: str = Query(..., description="State parameter for CSRF protection"),
    error: Optional[str] = Query(None, description="Error from OAuth provider"),
    error_description: Optional[str] = Query(None, description="Error description")
):
    """
    Handle OAuth callback with PKCE validation
    
    - **provider**: OAuth provider name
    - **code**: Authorization code from provider  
    - **state**: State parameter for validation
    - **error**: Optional error from provider
    - **error_description**: Optional error description
    """
    try:
        # Check for OAuth errors
        if error:
            logger.warning(f"OAuth error from {provider}: {error} - {error_description}")
            raise HTTPException(
                status_code=400,
                detail=f"OAuth authorization failed: {error} - {error_description}"
            )
        
        # Validate provider
        validate_provider(provider)
        config = OAUTH_CONFIG[provider]
        
        # Create OAuth provider
        redirect_uri = get_redirect_uri(provider, request)
        oauth_provider = create_oauth_provider(
            provider_name=provider,
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            redirect_uri=redirect_uri,
            tenant=config.get("tenant")
        )
        
        # Exchange code for tokens with PKCE validation
        token_response = await oauth_provider.exchange_code_with_pkce(
            authorization_code=code,
            state=state
        )
        
        # Get user information
        access_token = token_response.get("access_token")
        if access_token:
            user_info = await oauth_provider.get_user_info(access_token)
            
            # TODO: Create or update user account with OAuth info
            # This would integrate with your existing user management system
            
            logger.info(f"OAuth callback successful for {provider} - User: {user_info.get('id', 'unknown')}")
            
            # In a real implementation, you would:
            # 1. Create/update user account
            # 2. Generate JWT tokens
            # 3. Redirect to success page or return tokens
            
            # For now, return success response
            return {
                "success": True,
                "provider": provider,
                "user_info": user_info,
                "message": "OAuth authentication successful"
            }
        else:
            raise HTTPException(status_code=400, detail="No access token received")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OAuth callback failed for {provider}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"OAuth callback failed: {str(e)}")

@router.post("/{provider}/exchange", response_model=PKCETokenResponse)
async def exchange_authorization_code(
    provider: str,
    request: PKCECallbackRequest,
    http_request: Request
):
    """
    Exchange authorization code for tokens (alternative to callback)
    
    - **provider**: OAuth provider name
    - **request**: PKCE callback request data
    - **Returns**: Token response with access/refresh tokens
    """
    try:
        # Validate provider
        validate_provider(provider)
        config = OAUTH_CONFIG[provider]
        
        # Create OAuth provider
        redirect_uri = get_redirect_uri(provider, http_request)
        oauth_provider = create_oauth_provider(
            provider_name=provider,
            client_id=config["client_id"],
            client_secret=config["client_secret"],
            redirect_uri=redirect_uri,
            tenant=config.get("tenant")
        )
        
        # Exchange code for tokens with PKCE validation
        token_response = await oauth_provider.exchange_code_with_pkce(
            authorization_code=request.code,
            state=request.state
        )
        
        logger.info(f"Token exchange successful for {provider}")
        
        return PKCETokenResponse(
            access_token=token_response["access_token"],
            token_type=token_response.get("token_type", "Bearer"),
            expires_in=token_response.get("expires_in"),
            refresh_token=token_response.get("refresh_token"),
            scope=token_response.get("scope"),
            provider=provider
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token exchange failed for {provider}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {str(e)}")

@router.get("/providers")
async def list_oauth_providers():
    """
    List available OAuth providers and their configuration status
    
    Returns:
        Dictionary of available providers and their status
    """
    providers = {}
    
    for provider_name in OAUTH_PROVIDERS.keys():
        config = OAUTH_CONFIG.get(provider_name, {})
        providers[provider_name] = {
            "configured": bool(config.get("client_id") and config.get("client_secret")),
            "scopes": config.get("scopes", []),
            "authorization_endpoint": f"/oauth/{provider_name}/authorize",
            "callback_endpoint": f"/oauth/{provider_name}/callback"
        }
    
    return {
        "providers": providers,
        "total_configured": sum(1 for p in providers.values() if p["configured"]),
        "pkce_enabled": True,
        "oauth_version": "2.1"
    }

@router.get("/pkce/stats", response_model=PKCEStatsResponse)
async def get_pkce_stats():
    """
    Get PKCE statistics for monitoring
    
    Returns:
        PKCE statistics including active entries and cleanup status
    """
    try:
        pkce_service = await get_pkce_service()
        stats = await pkce_service.get_pkce_stats()
        
        return PKCEStatsResponse(**stats)
        
    except Exception as e:
        logger.error(f"Failed to get PKCE stats: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get PKCE stats: {str(e)}")

@router.post("/pkce/cleanup")
async def cleanup_expired_pkce():
    """
    Manually trigger cleanup of expired PKCE data
    
    Returns:
        Number of expired entries cleaned up
    """
    try:
        pkce_service = await get_pkce_service()
        cleaned_count = await pkce_service.cleanup_expired_pkce()
        
        return {
            "cleaned_entries": cleaned_count,
            "message": f"Cleaned up {cleaned_count} expired PKCE entries"
        }
        
    except Exception as e:
        logger.error(f"PKCE cleanup failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"PKCE cleanup failed: {str(e)}")

@router.get("/health")
async def oauth_health_check():
    """
    OAuth system health check
    
    Returns:
        OAuth system health status
    """
    try:
        # Check Redis connectivity
        pkce_service = await get_pkce_service()
        stats = await pkce_service.get_pkce_stats()
        
        # Check provider configurations
        configured_providers = [
            name for name, config in OAUTH_CONFIG.items()
            if config.get("client_id") and config.get("client_secret")
        ]
        
        return {
            "status": "healthy",
            "oauth_version": "2.1",
            "pkce_enabled": True,
            "redis_connected": "error" not in stats,
            "configured_providers": configured_providers,
            "active_pkce_entries": stats.get("active_pkce_entries", 0),
            "timestamp": stats.get("timestamp")
        }
        
    except Exception as e:
        logger.error(f"OAuth health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "oauth_version": "2.1",
            "pkce_enabled": True
        }