# Redis-JWT Hybrid Session Management System

## 🚀 Overview

The Ultimate Planner implements a sophisticated Redis-JWT hybrid session management system that provides:

- **Scalable Architecture**: Redis-based storage for production scalability
- **Security First**: Advanced session validation, blacklisting, and suspicious activity detection
- **Multi-Device Support**: Device fingerprinting and concurrent session management
- **Enterprise Features**: Session limits, activity tracking, and comprehensive audit logging

## 🏗️ Architecture

### Components

1. **RedisSessionService**: Core session management with Redis backend
2. **JWTService**: Enhanced JWT handling with session integration
3. **Session Middleware**: Request validation and activity tracking
4. **Session API**: RESTful endpoints for session management
5. **Database Models**: Optional persistent session storage

### Data Flow

```
Client Request → JWT Verification → Session Validation → Activity Update → Response
                      ↓                    ↓                    ↓
                 Token Blacklist    Redis Session      Activity Tracking
```

## 🔧 Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379/0
REDIS_DB=0
REDIS_PASSWORD=your-redis-password
REDIS_MAX_CONNECTIONS=10

# Session Management
SESSION_EXPIRE_SECONDS=3600        # 1 hour default
REMEMBER_ME_EXPIRE_SECONDS=2592000  # 30 days for "remember me"
MAX_SESSIONS_PER_USER=5             # Concurrent session limit

# JWT Configuration
SECRET_KEY=your-jwt-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Redis Keys Structure

| Key Pattern | Purpose | TTL |
|-------------|---------|-----|
| `session:{session_id}` | Session data | Configurable |
| `user_sessions:{user_id}` | User's session list | Max session TTL |
| `blacklist:{jwt_jti}` | Blacklisted tokens | Token expiry |
| `device_sessions:{user_id}:{fingerprint}` | Device tracking | Session TTL |

## 📡 API Endpoints

### Session Management

#### Get User Sessions
```http
GET /auth/sessions
Headers:
  Authorization: Bearer <jwt_token>
  X-Session-ID: <session_id>

Response:
{
  "sessions": [
    {
      "session_id": "uuid",
      "device_fingerprint": "hash",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "created_at": "2024-01-15T10:00:00Z",
      "last_activity": "2024-01-15T10:30:00Z",
      "remember_me": false,
      "is_current": true
    }
  ],
  "total_count": 3,
  "max_sessions": 5
}
```

#### Revoke Session
```http
DELETE /auth/sessions/{session_id}
Headers:
  Authorization: Bearer <jwt_token>

Response:
{
  "message": "Session revoked successfully"
}
```

#### Enhanced Login
```http
POST /auth/sessions/enhanced-login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password",
  "mfa_token": "123456",
  "remember_me": true,
  "device_info": {
    "device_type": "desktop",
    "os": "Windows 10",
    "browser": "Chrome"
  }
}

Response:
{
  "access_token": "jwt_token",
  "token_type": "bearer",
  "session_id": "uuid",
  "expires_in": 2592000,
  "mfa_verified": true,
  "user_id": 123
}
```

#### Refresh Token
```http
POST /auth/sessions/refresh
Headers:
  Authorization: Bearer <current_token>
  X-Session-ID: <session_id>

{
  "session_id": "uuid"
}

Response:
{
  "access_token": "new_jwt_token",
  "token_type": "bearer",
  "session_id": "uuid",
  "expires_in": 3600
}
```

#### Logout Current Session
```http
POST /auth/sessions/logout
Headers:
  Authorization: Bearer <jwt_token>
  X-Session-ID: <session_id>

Response:
{
  "message": "Logged out successfully"
}
```

#### Revoke All Sessions
```http
DELETE /auth/sessions/all

Response:
{
  "invalidated_count": 4,
  "message": "Successfully revoked all 4 sessions"
}
```

### Security Features

#### Security Analysis
```http
GET /auth/sessions/{session_id}/security

Response:
{
  "session_id": "uuid",
  "risk_score": 0.3,
  "suspicious_activity": [
    "New IP address"
  ],
  "recommendations": [
    "Monitor for unauthorized access from new locations"
  ],
  "last_security_check": "2024-01-15T10:30:00Z"
}
```

#### Session Statistics
```http
GET /auth/sessions/stats

Response:
{
  "active_sessions": 3,
  "total_sessions_created": 15,
  "blacklisted_tokens": 2,
  "redis_health": {
    "status": "healthy",
    "connected_clients": 5,
    "used_memory": "1.2MB",
    "uptime_in_seconds": 86400,
    "redis_version": "6.2.6"
  }
}
```

## 🔐 Security Features

### 1. Token Blacklisting

- JWT tokens are blacklisted in Redis on logout
- Blacklist entries automatically expire with token expiry
- Prevents token reuse after logout/revocation

### 2. Device Fingerprinting

- Generates unique fingerprints from IP + User-Agent
- Tracks device changes for security monitoring
- Enables device-specific session management

### 3. Session Limits

- Configurable maximum concurrent sessions per user
- Automatically removes oldest sessions when limit exceeded
- Prevents session hoarding attacks

### 4. Activity Tracking

- Updates last activity timestamp on each request
- Enables idle session detection
- Provides audit trail for security reviews

### 5. Suspicious Activity Detection

- Monitors multiple IP addresses
- Detects rapid session creation
- Identifies new device access patterns
- Calculates risk scores for sessions

### 6. Rate Limiting Integration

Built to work with rate limiting middleware:
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@router.post("/sessions/enhanced-login")
@limiter.limit("5/minute")
async def enhanced_login(request: Request, ...):
    # Enhanced login logic
```

## 🛠️ Implementation Details

### RedisSessionService

```python
from app.services.redis_session_service import RedisSessionService

# Create session
redis_session = RedisSessionService()
session_id = await redis_session.create_session(
    user_id=user.id,
    jwt_token=token,
    device_info={"ip": "192.168.1.1", "user_agent": "..."},
    remember_me=True
)

# Validate session
is_valid = await redis_session.validate_session(session_id, token)

# Get user sessions
sessions = await redis_session.get_user_sessions(user.id)

# Invalidate session
await redis_session.invalidate_session(session_id)
```

### JWTService Integration

```python
from app.services.jwt_service import JWTService

jwt_service = JWTService()

# Create session with token
result = await jwt_service.create_session_with_token(
    user_id=str(user.id),
    request=request,
    remember_me=False
)

# Validate token with session
payload = await jwt_service.validate_token_with_session(
    token=jwt_token,
    session_id=session_id
)

# Refresh token
new_token_data = await jwt_service.refresh_token_with_session(
    current_token=old_token,
    session_id=session_id,
    request=request
)
```

### Enhanced Dependencies

```python
from app.auth.dependencies import get_current_user

@router.get("/protected")
async def protected_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    # User is authenticated with session validation
    return {"user_id": current_user.id}
```

## 📊 Monitoring & Analytics

### Health Checks

Monitor Redis connectivity:
```python
from app.config.redis_config import ping_redis

redis_healthy = await ping_redis()
if not redis_healthy:
    # Handle Redis failure
    pass
```

### Session Cleanup

Background task for maintenance:
```python
from app.services.redis_session_service import RedisSessionService

async def cleanup_expired_sessions():
    redis_session = RedisSessionService()
    cleaned_count = await redis_session.cleanup_expired_sessions()
    logger.info(f"Cleaned up {cleaned_count} expired sessions")
```

### Performance Metrics

Track key metrics:
- Active sessions per user
- Session creation/destruction rates
- Token blacklist size
- Redis memory usage
- Average session duration

## 🚀 Deployment Considerations

### Production Setup

1. **Redis Configuration**
   ```bash
   # Redis persistence
   appendonly yes
   appendfsync everysec
   
   # Memory management
   maxmemory 2gb
   maxmemory-policy allkeys-lru
   
   # Security
   requirepass your_strong_password
   ```

2. **Connection Pooling**
   - Configure appropriate pool size for your load
   - Monitor connection usage
   - Implement connection retry logic

3. **Backup Strategy**
   - Regular Redis backups for session persistence
   - Consider Redis Cluster for high availability
   - Implement session data recovery procedures

### Scaling Considerations

- **Horizontal Scaling**: Use Redis Cluster for multi-node deployment
- **Load Balancing**: Session stickiness not required with Redis backend
- **Caching**: Implement local caching for frequently accessed sessions
- **Monitoring**: Use Redis monitoring tools (RedisInsight, Redis CLI)

## 🐛 Troubleshooting

### Common Issues

1. **Redis Connection Failures**
   ```python
   # Implement graceful degradation
   try:
       session_valid = await redis_session.validate_session(...)
   except RedisError:
       # Fallback to JWT-only validation
       payload = jwt_service.verify_token(token)
   ```

2. **Session Cleanup Issues**
   - Check Redis memory usage
   - Verify TTL settings
   - Monitor expired key cleanup

3. **Performance Issues**
   - Optimize Redis operations
   - Implement connection pooling
   - Use Redis pipelining for bulk operations

### Debug Commands

```bash
# Check Redis connectivity
redis-cli ping

# Monitor Redis operations
redis-cli monitor

# Check session keys
redis-cli keys "session:*"

# Get session data
redis-cli get "session:uuid"

# Check blacklisted tokens
redis-cli keys "blacklist:*"
```

## 🔒 Security Best Practices

1. **Token Security**
   - Use strong JWT secrets
   - Implement token rotation
   - Monitor for token abuse

2. **Session Security**
   - Enforce session timeouts
   - Implement device verification
   - Monitor suspicious patterns

3. **Redis Security**
   - Use authentication
   - Enable SSL/TLS
   - Restrict network access
   - Regular security updates

4. **Audit Logging**
   - Log all session events
   - Monitor authentication patterns
   - Implement alerting for suspicious activity

## 📈 Future Enhancements

1. **Advanced Analytics**
   - User behavior tracking
   - Geographic access patterns
   - Device usage statistics

2. **Enhanced Security**
   - Biometric verification
   - Risk-based authentication
   - Machine learning fraud detection

3. **Performance Optimizations**
   - Session data compression
   - Predictive preloading
   - Smart caching strategies

4. **Integration Features**
   - SSO compatibility
   - OAuth 2.0 enhancements
   - Enterprise directory integration

---

This Redis-JWT hybrid session system provides enterprise-grade session management with the scalability of Redis and the security of JWT tokens, ensuring robust authentication for production applications.