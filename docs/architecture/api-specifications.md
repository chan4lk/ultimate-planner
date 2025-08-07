# API Specifications - Enterprise Authentication System

## Overview
This document provides comprehensive API specifications for the enterprise authentication system, including request/response schemas, security requirements, and implementation details.

## Base Configuration
```
Base URL: https://api.ultimate-planner.com
API Version: v1
Content-Type: application/json
Rate Limiting: Varies by endpoint (see individual endpoints)
Authentication: Bearer JWT tokens
```

## Authentication Endpoints

### 1. User Registration
```http
POST /auth/register
Content-Type: application/json
Rate-Limit: 3/hour per IP

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "SecurePassword123!",
  "confirm_password": "SecurePassword123!",
  "terms_accepted": true,
  "marketing_consent": false
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "username": "johndoe",
      "email_verified": false,
      "created_at": "2024-01-15T10:30:00Z"
    },
    "tokens": {
      "access_token": "eyJhbGciOiJSUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
      "token_type": "Bearer",
      "expires_in": 900
    }
  },
  "message": "Registration successful. Please verify your email."
}
```

**Error Response (400 Bad Request):**
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Email already registered",
    "details": {
      "field": "email",
      "constraint": "unique_violation"
    }
  }
}
```

### 2. User Login
```http
POST /auth/login
Content-Type: application/json
Rate-Limit: 5/minute per IP, 10/hour per email

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "remember_me": true,
  "device_info": {
    "device_id": "device-12345",
    "device_name": "iPhone 15 Pro",
    "os": "iOS 17.1",
    "browser": "Safari 17.0"
  }
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "username": "johndoe",
      "mfa_enabled": true,
      "last_login_at": "2024-01-15T09:30:00Z"
    },
    "tokens": {
      "access_token": "eyJhbGciOiJSUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
      "token_type": "Bearer",
      "expires_in": 900
    },
    "session": {
      "id": "sess_123e4567-e89b-12d3-a456-426614174000",
      "expires_at": "2024-01-16T10:30:00Z"
    },
    "mfa_required": false
  }
}
```

**MFA Challenge Response (202 Accepted):**
```json
{
  "success": true,
  "data": {
    "mfa_required": true,
    "challenge_token": "temp_token_123",
    "available_methods": ["totp", "backup_code"],
    "expires_in": 300
  },
  "message": "MFA verification required"
}
```

### 3. MFA Verification
```http
POST /auth/mfa/verify
Content-Type: application/json
Rate-Limit: 3/minute per user
Authorization: Bearer {challenge_token}

{
  "method": "totp",
  "code": "123456",
  "remember_device": false
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "username": "johndoe"
    },
    "tokens": {
      "access_token": "eyJhbGciOiJSUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
      "token_type": "Bearer",
      "expires_in": 900
    },
    "session": {
      "id": "sess_123e4567-e89b-12d3-a456-426614174000",
      "expires_at": "2024-01-16T10:30:00Z"
    }
  }
}
```

### 4. Token Refresh
```http
POST /auth/refresh
Content-Type: application/json
Rate-Limit: 20/hour per user

{
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "tokens": {
      "access_token": "eyJhbGciOiJSUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
      "token_type": "Bearer",
      "expires_in": 900
    }
  }
}
```

### 5. Logout
```http
POST /auth/logout
Authorization: Bearer {access_token}
Rate-Limit: 10/minute per user

{
  "logout_all_devices": false
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

## Multi-Factor Authentication Endpoints

### 1. MFA Setup Initiation
```http
POST /auth/mfa/setup
Authorization: Bearer {access_token}
Rate-Limit: 3/hour per user

{
  "method": "totp"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "setup_token": "setup_123456789",
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
    "backup_codes": [
      "12345678",
      "23456789",
      "34567890"
    ],
    "expires_in": 300
  },
  "message": "Scan QR code with your authenticator app"
}
```

### 2. MFA Setup Verification
```http
POST /auth/mfa/verify-setup
Authorization: Bearer {setup_token}
Rate-Limit: 5/minute per user

{
  "code": "123456"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "mfa_enabled": true,
    "backup_codes": [
      "12345678",
      "23456789",
      "34567890"
    ]
  },
  "message": "MFA successfully enabled. Save your backup codes."
}
```

### 3. Generate New Backup Codes
```http
POST /auth/mfa/backup-codes/regenerate
Authorization: Bearer {access_token}
Rate-Limit: 2/hour per user

{
  "current_password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "backup_codes": [
      "87654321",
      "76543210",
      "65432109"
    ]
  },
  "message": "New backup codes generated. Previous codes are now invalid."
}
```

### 4. Disable MFA
```http
POST /auth/mfa/disable
Authorization: Bearer {access_token}
Rate-Limit: 1/hour per user

{
  "current_password": "SecurePassword123!",
  "confirmation_code": "123456"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "MFA has been disabled"
}
```

## OAuth 2.1 Endpoints

### 1. OAuth Authorization
```http
GET /oauth/authorize/{provider}
Parameters:
  - provider: microsoft | notion | google
  - scopes: optional comma-separated list
Rate-Limit: 10/minute per user

Authorization: Bearer {access_token}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=...",
    "state": "secure_random_state_123456",
    "code_challenge": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "code_challenge_method": "S256",
    "expires_in": 600
  }
}
```

### 2. OAuth Callback
```http
GET /oauth/callback/{provider}
Parameters:
  - code: authorization_code_from_provider
  - state: state_parameter_from_authorization
Rate-Limit: 5/minute per IP

```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "integration": {
      "id": "int_123e4567-e89b-12d3-a456-426614174000",
      "provider": "microsoft",
      "provider_user_id": "user@microsoft.com",
      "scopes": ["Tasks.ReadWrite", "User.Read"],
      "status": "active",
      "connected_at": "2024-01-15T10:30:00Z"
    },
    "user_info": {
      "name": "John Doe",
      "email": "john.doe@microsoft.com",
      "avatar_url": "https://graph.microsoft.com/v1.0/me/photo/$value"
    }
  },
  "message": "Microsoft integration successful"
}
```

### 3. OAuth Revocation
```http
DELETE /oauth/revoke/{provider}
Authorization: Bearer {access_token}
Rate-Limit: 5/minute per user

{
  "reason": "user_requested"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Microsoft integration revoked successfully"
}
```

## Password Management Endpoints

### 1. Change Password
```http
PUT /auth/password/change
Authorization: Bearer {access_token}
Rate-Limit: 3/hour per user

{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword456!",
  "confirm_password": "NewPassword456!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "password_changed_at": "2024-01-15T10:30:00Z",
    "sessions_terminated": 3
  },
  "message": "Password changed successfully. Please log in again."
}
```

### 2. Request Password Reset
```http
POST /auth/password/reset
Rate-Limit: 3/hour per email

{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "If the email exists, a reset link has been sent."
}
```

### 3. Complete Password Reset
```http
POST /auth/password/reset/complete
Rate-Limit: 5/minute per IP

{
  "token": "reset_token_123456789",
  "new_password": "NewPassword789!",
  "confirm_password": "NewPassword789!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset successful. Please log in."
}
```

## User Profile Endpoints

### 1. Get Current User Profile
```http
GET /users/me
Authorization: Bearer {access_token}
Rate-Limit: 100/hour per user
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "username": "johndoe",
      "email_verified": true,
      "mfa_enabled": true,
      "roles": ["user"],
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z",
      "last_login_at": "2024-01-15T10:30:00Z",
      "settings": {
        "notifications": {
          "email": true,
          "push": false
        },
        "privacy": {
          "profile_visibility": "private"
        }
      }
    },
    "integrations": [
      {
        "id": "int_123",
        "provider": "microsoft",
        "status": "active",
        "connected_at": "2024-01-10T00:00:00Z"
      }
    ],
    "active_sessions": 2
  }
}
```

### 2. Update User Profile
```http
PUT /users/me
Authorization: Bearer {access_token}
Rate-Limit: 10/hour per user

{
  "username": "johndoe_updated",
  "settings": {
    "notifications": {
      "email": false,
      "push": true
    }
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "username": "johndoe_updated",
      "updated_at": "2024-01-15T10:35:00Z"
    }
  },
  "message": "Profile updated successfully"
}
```

### 3. Get Active Sessions
```http
GET /users/me/sessions
Authorization: Bearer {access_token}
Rate-Limit: 20/hour per user
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "sessions": [
      {
        "id": "sess_123",
        "device_info": {
          "device_name": "iPhone 15 Pro",
          "os": "iOS 17.1",
          "browser": "Safari 17.0"
        },
        "ip_address": "192.168.1.100",
        "location": "San Francisco, CA, US",
        "is_current": true,
        "created_at": "2024-01-15T10:30:00Z",
        "last_used_at": "2024-01-15T10:35:00Z",
        "expires_at": "2024-01-16T10:30:00Z"
      }
    ],
    "total": 2
  }
}
```

### 4. Terminate Session
```http
DELETE /users/me/sessions/{session_id}
Authorization: Bearer {access_token}
Rate-Limit: 10/minute per user
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Session terminated successfully"
}
```

## Admin Endpoints

### 1. List Users (Admin Only)
```http
GET /admin/users
Authorization: Bearer {access_token}
Permissions: user.read
Rate-Limit: 100/hour per admin

Parameters:
  - page: integer (default: 1)
  - limit: integer (default: 20, max: 100)
  - search: string (search in email, username)
  - role: string (filter by role)
  - status: active|inactive|locked
  - sort: created_at|last_login_at|email
  - order: asc|desc
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "email": "user@example.com",
        "username": "johndoe",
        "is_active": true,
        "email_verified": true,
        "mfa_enabled": true,
        "roles": ["user"],
        "failed_login_attempts": 0,
        "locked_until": null,
        "created_at": "2024-01-01T00:00:00Z",
        "last_login_at": "2024-01-15T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 1500,
      "total_pages": 75,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

### 2. Get User Details (Admin Only)
```http
GET /admin/users/{user_id}
Authorization: Bearer {access_token}
Permissions: user.read
Rate-Limit: 200/hour per admin
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "username": "johndoe",
      "is_active": true,
      "email_verified": true,
      "mfa_enabled": true,
      "roles": ["user"],
      "failed_login_attempts": 0,
      "locked_until": null,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T10:30:00Z",
      "last_login_at": "2024-01-15T10:30:00Z",
      "last_login_ip": "192.168.1.100"
    },
    "integrations": [
      {
        "id": "int_123",
        "provider": "microsoft",
        "status": "active",
        "connected_at": "2024-01-10T00:00:00Z",
        "last_sync_at": "2024-01-15T10:00:00Z"
      }
    ],
    "active_sessions": 2,
    "recent_activity": [
      {
        "event_type": "login",
        "success": true,
        "created_at": "2024-01-15T10:30:00Z",
        "ip_address": "192.168.1.100"
      }
    ]
  }
}
```

### 3. Update User (Admin Only)
```http
PUT /admin/users/{user_id}
Authorization: Bearer {access_token}
Permissions: user.update
Rate-Limit: 50/hour per admin

{
  "is_active": true,
  "email_verified": true,
  "failed_login_attempts": 0,
  "locked_until": null
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "is_active": true,
      "updated_at": "2024-01-15T10:35:00Z"
    }
  },
  "message": "User updated successfully"
}
```

### 4. Unlock User Account (Admin Only)
```http
POST /admin/users/{user_id}/unlock
Authorization: Bearer {access_token}
Permissions: user.update
Rate-Limit: 20/hour per admin

{
  "reason": "Account review completed"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User account unlocked successfully"
}
```

### 5. Get Security Audit Logs (Admin Only)
```http
GET /admin/audit-logs
Authorization: Bearer {access_token}
Permissions: audit.read
Rate-Limit: 50/hour per admin

Parameters:
  - page: integer (default: 1)
  - limit: integer (default: 50, max: 200)
  - user_id: string (filter by user)
  - event_type: string (filter by event type)
  - event_category: auth|mfa|password|oauth|admin|security
  - success: true|false
  - start_date: ISO 8601 datetime
  - end_date: ISO 8601 datetime
  - ip_address: string
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": "log_123e4567-e89b-12d3-a456-426614174000",
        "user_id": "123e4567-e89b-12d3-a456-426614174000",
        "event_type": "login",
        "event_category": "auth",
        "success": true,
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "location_info": {
          "country": "US",
          "city": "San Francisco",
          "region": "CA"
        },
        "event_data": {
          "login_method": "password",
          "mfa_required": true
        },
        "risk_score": 10,
        "created_at": "2024-01-15T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 15000,
      "total_pages": 300,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

## Role Management Endpoints

### 1. List Roles (Admin Only)
```http
GET /admin/roles
Authorization: Bearer {access_token}
Permissions: role.read
Rate-Limit: 100/hour per admin
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "roles": [
      {
        "id": "role_123e4567-e89b-12d3-a456-426614174000",
        "name": "admin",
        "description": "Application administrator",
        "permissions": ["user.*", "role.*", "audit.*"],
        "is_system_role": true,
        "user_count": 5,
        "created_at": "2024-01-01T00:00:00Z"
      }
    ]
  }
}
```

### 2. Assign Role to User (Admin Only)
```http
POST /admin/users/{user_id}/roles/{role_id}
Authorization: Bearer {access_token}
Permissions: role.assign
Rate-Limit: 20/hour per admin

{
  "expires_at": "2024-12-31T23:59:59Z", // Optional
  "reason": "Promoting to team lead"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Role assigned successfully"
}
```

## Error Responses

### Standard Error Format
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "specific_field",
      "constraint": "validation_rule"
    },
    "trace_id": "trace_123456789"
  }
}
```

### Common Error Codes
- `VALIDATION_ERROR`: Request validation failed
- `AUTHENTICATION_REQUIRED`: Valid authentication required
- `INSUFFICIENT_PERMISSIONS`: User lacks required permissions
- `RATE_LIMIT_EXCEEDED`: Rate limit exceeded for endpoint
- `RESOURCE_NOT_FOUND`: Requested resource doesn't exist
- `MFA_REQUIRED`: Multi-factor authentication required
- `TOKEN_EXPIRED`: JWT token has expired
- `ACCOUNT_LOCKED`: User account is locked
- `OAUTH_ERROR`: OAuth provider error
- `INTERNAL_ERROR`: Internal server error

### HTTP Status Codes
- `200`: Success
- `201`: Created
- `202`: Accepted (async operation)
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `409`: Conflict
- `422`: Unprocessable Entity
- `429`: Too Many Requests
- `500`: Internal Server Error

## Security Headers

All API responses include security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## Rate Limiting

Rate limits are implemented with different strategies:
- **IP-based**: Prevent abuse from specific IPs
- **User-based**: Prevent abuse from authenticated users
- **Global**: Overall system protection

Rate limit headers included in responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
X-RateLimit-Retry-After: 60
```

This comprehensive API specification provides the foundation for implementing the enterprise authentication system with proper security, error handling, and scalability considerations.