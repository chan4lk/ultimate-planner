# Redis Session System - Quick Start Guide

## 🚀 Setup & Installation

### 1. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt
# or
pip install redis>=4.5.0 aioredis>=2.0.0

# Start Redis server (using Docker)
docker run -d --name redis-session -p 6379:6379 redis:7-alpine

# Or install Redis locally
# macOS: brew install redis && brew services start redis
# Ubuntu: sudo apt install redis-server && sudo systemctl start redis
```

### 2. Environment Configuration

Create `.env` file from template:
```bash
cp .env.example .env
```

Configure Redis settings:
```env
REDIS_URL=redis://localhost:6379/0
SESSION_EXPIRE_SECONDS=3600
REMEMBER_ME_EXPIRE_SECONDS=2592000
MAX_SESSIONS_PER_USER=5
```

### 3. Database Migration

```bash
# Run Alembic migrations
alembic upgrade head
```

### 4. Start Application

```bash
uvicorn app.main:app --reload --port 8000
```

## 📝 Basic Usage

### Enhanced Login with Session Management

```python
import httpx

# Enhanced login request
response = httpx.post("http://localhost:8000/auth/sessions/enhanced-login", json={
    "email": "user@example.com",
    "password": "password123",
    "remember_me": True,
    "device_info": {
        "device_type": "desktop",
        "os": "Windows 10",
        "browser": "Chrome"
    }
})

data = response.json()
access_token = data["access_token"]
session_id = data["session_id"]
```

### Making Authenticated Requests

```python
headers = {
    "Authorization": f"Bearer {access_token}",
    "X-Session-ID": session_id
}

# Get user sessions
response = httpx.get("http://localhost:8000/auth/sessions", headers=headers)
sessions = response.json()["sessions"]
```

### Session Management

```python
# Refresh token
response = httpx.post(
    "http://localhost:8000/auth/sessions/refresh",
    headers=headers,
    json={"session_id": session_id}
)

new_token = response.json()["access_token"]

# Revoke specific session
httpx.delete(f"http://localhost:8000/auth/sessions/{other_session_id}", headers=headers)

# Logout all sessions
httpx.delete("http://localhost:8000/auth/sessions/all", headers=headers)

# Logout current session
httpx.post("http://localhost:8000/auth/sessions/logout", headers=headers)
```

## 🔧 Client Integration Examples

### JavaScript/TypeScript

```typescript
class SessionManager {
    private accessToken: string;
    private sessionId: string;

    async login(email: string, password: string, rememberMe: boolean = false) {
        const response = await fetch('/auth/sessions/enhanced-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                remember_me: rememberMe,
                device_info: {
                    device_type: 'web',
                    os: navigator.platform,
                    browser: navigator.userAgent.split(' ')[0]
                }
            })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access_token;
            this.sessionId = data.session_id;
            
            localStorage.setItem('access_token', this.accessToken);
            localStorage.setItem('session_id', this.sessionId);
            return data;
        }
        throw new Error('Login failed');
    }

    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.accessToken}`,
            'X-Session-ID': this.sessionId
        };
    }

    async refreshToken() {
        const response = await fetch('/auth/sessions/refresh', {
            method: 'POST',
            headers: {
                ...this.getAuthHeaders(),
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ session_id: this.sessionId })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access_token;
            localStorage.setItem('access_token', this.accessToken);
            return data;
        }
        throw new Error('Token refresh failed');
    }

    async logout() {
        await fetch('/auth/sessions/logout', {
            method: 'POST',
            headers: this.getAuthHeaders()
        });
        
        localStorage.removeItem('access_token');
        localStorage.removeItem('session_id');
        this.accessToken = '';
        this.sessionId = '';
    }
}
```

### React Hook

```tsx
import { useState, useEffect } from 'react';

interface Session {
    session_id: string;
    device_fingerprint: string;
    ip_address: string;
    user_agent: string;
    created_at: string;
    last_activity: string;
    remember_me: boolean;
    is_current: boolean;
}

export const useSession = () => {
    const [sessions, setSessions] = useState<Session[]>([]);
    const [loading, setLoading] = useState(false);

    const fetchSessions = async () => {
        setLoading(true);
        try {
            const response = await fetch('/auth/sessions', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'X-Session-ID': localStorage.getItem('session_id')!
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                setSessions(data.sessions);
            }
        } catch (error) {
            console.error('Failed to fetch sessions:', error);
        } finally {
            setLoading(false);
        }
    };

    const revokeSession = async (sessionId: string) => {
        try {
            const response = await fetch(`/auth/sessions/${sessionId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                    'X-Session-ID': localStorage.getItem('session_id')!
                }
            });
            
            if (response.ok) {
                setSessions(prev => prev.filter(s => s.session_id !== sessionId));
            }
        } catch (error) {
            console.error('Failed to revoke session:', error);
        }
    };

    useEffect(() => {
        fetchSessions();
    }, []);

    return {
        sessions,
        loading,
        fetchSessions,
        revokeSession
    };
};
```

### Mobile (React Native)

```typescript
import AsyncStorage from '@react-native-async-storage/async-storage';
import DeviceInfo from 'react-native-device-info';

class MobileSessionManager {
    async login(email: string, password: string) {
        const deviceInfo = {
            device_type: 'mobile',
            os: await DeviceInfo.getSystemName(),
            browser: await DeviceInfo.getApplicationName(),
            device_fingerprint: await DeviceInfo.getUniqueId()
        };

        const response = await fetch('/auth/sessions/enhanced-login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                remember_me: true, // Mobile apps typically want persistent sessions
                device_info: deviceInfo
            })
        });

        if (response.ok) {
            const data = await response.json();
            await AsyncStorage.multiSet([
                ['access_token', data.access_token],
                ['session_id', data.session_id]
            ]);
            return data;
        }
        throw new Error('Login failed');
    }

    async makeAuthenticatedRequest(url: string, options: RequestInit = {}) {
        const [accessToken, sessionId] = await AsyncStorage.multiGet([
            'access_token',
            'session_id'
        ]);

        return fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${accessToken[1]}`,
                'X-Session-ID': sessionId[1]
            }
        });
    }
}
```

## 🔒 Security Best Practices

### 1. Token Storage

```javascript
// ❌ Don't store in localStorage for sensitive apps
localStorage.setItem('access_token', token);

// ✅ Use secure storage
// For web: httpOnly cookies or secure storage libraries
// For mobile: Keychain (iOS) / Keystore (Android)

// Example with js-cookie for httpOnly cookies
import Cookies from 'js-cookie';
Cookies.set('access_token', token, { 
    secure: true, 
    httpOnly: true, 
    sameSite: 'strict' 
});
```

### 2. Request Interceptors

```typescript
// Axios interceptor for automatic token refresh
axios.interceptors.response.use(
    response => response,
    async error => {
        if (error.response?.status === 401) {
            try {
                const sessionManager = new SessionManager();
                await sessionManager.refreshToken();
                // Retry original request
                return axios.request(error.config);
            } catch (refreshError) {
                // Redirect to login
                window.location.href = '/login';
            }
        }
        return Promise.reject(error);
    }
);
```

### 3. Session Monitoring

```typescript
// Monitor session activity
setInterval(async () => {
    try {
        const response = await fetch('/auth/sessions/stats', {
            headers: sessionManager.getAuthHeaders()
        });
        
        if (response.ok) {
            const stats = await response.json();
            console.log('Active sessions:', stats.active_sessions);
        }
    } catch (error) {
        console.error('Session check failed:', error);
    }
}, 60000); // Check every minute
```

## 🐛 Common Issues & Solutions

### 1. Redis Connection Issues

```python
# Check Redis connectivity
from app.config.redis_config import ping_redis

try:
    healthy = await ping_redis()
    if not healthy:
        print("Redis server not available")
except Exception as e:
    print(f"Redis error: {e}")
```

### 2. Session Validation Failures

```python
# Debug session validation
from app.services.redis_session_service import RedisSessionService

redis_session = RedisSessionService()
session_data = await redis_session.get_session_data(session_id)

if not session_data:
    print("Session not found or expired")
elif not session_data.get("is_active"):
    print("Session is inactive")
else:
    print("Session is valid")
```

### 3. Token Refresh Issues

```javascript
// Handle refresh failures gracefully
try {
    const newToken = await sessionManager.refreshToken();
    console.log('Token refreshed successfully');
} catch (error) {
    if (error.message === 'Token refresh failed') {
        // Force re-login
        await sessionManager.logout();
        window.location.href = '/login';
    }
}
```

## 📊 Monitoring & Debugging

### Redis CLI Commands

```bash
# Check all session keys
redis-cli keys "session:*"

# Get session data
redis-cli get "session:your-session-id"

# Check user sessions
redis-cli smembers "user_sessions:123"

# Monitor real-time operations
redis-cli monitor

# Check blacklisted tokens
redis-cli keys "blacklist:*"
```

### Application Logs

```python
import logging

# Configure logging for session management
logging.getLogger('app.services.redis_session_service').setLevel(logging.DEBUG)
logging.getLogger('app.services.jwt_service').setLevel(logging.DEBUG)
```

### Health Check Endpoint

```python
@app.get("/health/sessions")
async def session_health():
    from app.config.redis_config import ping_redis
    
    redis_healthy = await ping_redis()
    
    return {
        "redis_connection": "healthy" if redis_healthy else "unhealthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
```

## 🚀 Production Deployment

### Docker Compose Example

```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379/0
      - DATABASE_URL=postgresql://user:pass@db:5432/ultimate_planner
    depends_on:
      - redis
      - db

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

  db:
    image: postgres:15
    environment:
      POSTGRES_DB: ultimate_planner
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  redis_data:
  postgres_data:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ultimate-planner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ultimate-planner
  template:
    metadata:
      labels:
        app: ultimate-planner
    spec:
      containers:
      - name: app
        image: ultimate-planner:latest
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379/0"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: database-url
```

This quick start guide should get you up and running with the Redis session management system quickly and securely!