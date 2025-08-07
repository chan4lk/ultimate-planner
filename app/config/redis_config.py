"""Redis configuration and connection management."""

import os
import redis.asyncio as redis
from redis.asyncio import ConnectionPool
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Redis Configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))

# Session Configuration
SESSION_EXPIRE_SECONDS = int(os.getenv("SESSION_EXPIRE_SECONDS", "3600"))  # 1 hour default
REMEMBER_ME_EXPIRE_SECONDS = int(os.getenv("REMEMBER_ME_EXPIRE_SECONDS", "2592000"))  # 30 days
MAX_SESSIONS_PER_USER = int(os.getenv("MAX_SESSIONS_PER_USER", "5"))

# Session Redis Keys
SESSION_KEY_PREFIX = "session:"
USER_SESSIONS_KEY_PREFIX = "user_sessions:"
BLACKLIST_KEY_PREFIX = "blacklist:"
DEVICE_SESSIONS_KEY_PREFIX = "device_sessions:"

# Redis Connection Pool
_redis_pool: Optional[ConnectionPool] = None
_redis_client: Optional[redis.Redis] = None


async def get_redis_pool() -> ConnectionPool:
    """Get Redis connection pool."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = ConnectionPool.from_url(
            REDIS_URL,
            password=REDIS_PASSWORD,
            max_connections=REDIS_MAX_CONNECTIONS,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30
        )
    return _redis_pool


async def get_redis_client() -> redis.Redis:
    """Get Redis client instance."""
    global _redis_client
    if _redis_client is None:
        pool = await get_redis_pool()
        _redis_client = redis.Redis(connection_pool=pool)
    return _redis_client


async def close_redis_connections():
    """Close Redis connections."""
    global _redis_client, _redis_pool
    
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
    
    if _redis_pool:
        await _redis_pool.aclose()
        _redis_pool = None


async def ping_redis() -> bool:
    """Test Redis connection."""
    try:
        client = await get_redis_client()
        await client.ping()
        return True
    except Exception:
        return False


class RedisKeyBuilder:
    """Build Redis keys with consistent naming."""
    
    @staticmethod
    def session_key(session_id: str) -> str:
        """Build session key."""
        return f"{SESSION_KEY_PREFIX}{session_id}"
    
    @staticmethod
    def user_sessions_key(user_id: int) -> str:
        """Build user sessions list key."""
        return f"{USER_SESSIONS_KEY_PREFIX}{user_id}"
    
    @staticmethod
    def blacklist_key(token_jti: str) -> str:
        """Build token blacklist key."""
        return f"{BLACKLIST_KEY_PREFIX}{token_jti}"
    
    @staticmethod
    def device_sessions_key(user_id: int, device_fingerprint: str) -> str:
        """Build device sessions key."""
        return f"{DEVICE_SESSIONS_KEY_PREFIX}{user_id}:{device_fingerprint}"