# Database Schema Evolution Plan

## Overview
This document outlines the step-by-step database schema evolution to support enterprise-grade authentication features while maintaining backward compatibility.

## Current Schema Analysis

### Existing Tables
```sql
-- Current users table structure
users (
    id VARCHAR PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    username VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
)

-- Current user_integrations table
user_integrations (
    id VARCHAR PRIMARY KEY,
    user_id VARCHAR REFERENCES users(id),
    source VARCHAR NOT NULL,
    auth_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    sync_status VARCHAR,
    configuration JSONB,
    created_at TIMESTAMP DEFAULT NOW()
)
```

## Migration Strategy

### Migration 1: Enhanced User Security
```sql
-- Add security-related columns to users table
ALTER TABLE users 
ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE,
ADD COLUMN mfa_secret_encrypted TEXT,
ADD COLUMN backup_codes_hash TEXT,
ADD COLUMN password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
ADD COLUMN failed_login_attempts INTEGER DEFAULT 0,
ADD COLUMN locked_until TIMESTAMP WITH TIME ZONE,
ADD COLUMN last_login_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN last_login_ip INET,
ADD COLUMN email_verified BOOLEAN DEFAULT FALSE,
ADD COLUMN email_verification_token VARCHAR(128),
ADD COLUMN password_reset_token VARCHAR(128),
ADD COLUMN password_reset_expires_at TIMESTAMP WITH TIME ZONE;

-- Create indexes for performance
CREATE INDEX idx_users_mfa_enabled ON users(mfa_enabled) WHERE mfa_enabled = TRUE;
CREATE INDEX idx_users_locked ON users(locked_until) WHERE locked_until > NOW();
CREATE INDEX idx_users_failed_logins ON users(failed_login_attempts) WHERE failed_login_attempts > 0;
```

### Migration 2: Multi-Factor Authentication
```sql
-- MFA configurations table
CREATE TABLE user_mfa_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(20) NOT NULL CHECK (method IN ('totp', 'sms', 'email')),
    secret_encrypted TEXT NOT NULL,
    backup_codes_hash TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    phone_number VARCHAR(20), -- For SMS MFA
    recovery_email VARCHAR(255), -- For email MFA
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    verified_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT unique_user_method UNIQUE (user_id, method)
);

-- MFA backup codes tracking
CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(128) NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT unique_user_code UNIQUE (user_id, code_hash)
);

-- Indexes
CREATE INDEX idx_mfa_configs_user ON user_mfa_configs(user_id);
CREATE INDEX idx_mfa_configs_verified ON user_mfa_configs(user_id, is_verified);
CREATE INDEX idx_backup_codes_user ON mfa_backup_codes(user_id) WHERE used_at IS NULL;
```

### Migration 3: Session Management
```sql
-- Enhanced session tracking
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(128) UNIQUE NOT NULL,
    refresh_token_hash VARCHAR(128) UNIQUE NOT NULL,
    jti VARCHAR(128) UNIQUE NOT NULL, -- JWT ID for blacklisting
    device_info JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    location_info JSONB DEFAULT '{}', -- Country, city from IP
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_expiry CHECK (expires_at > created_at)
);

-- Token blacklist for JWT revocation
CREATE TABLE blacklisted_tokens (
    jti VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_type VARCHAR(20) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    reason VARCHAR(50) DEFAULT 'logout', -- 'logout', 'security', 'admin'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    blacklisted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    blacklisted_by VARCHAR -- User ID who initiated blacklisting
);

-- Indexes for performance
CREATE INDEX idx_sessions_user_active ON user_sessions(user_id, is_active, expires_at);
CREATE INDEX idx_sessions_token_hash ON user_sessions(session_token_hash);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_blacklisted_tokens_expires ON blacklisted_tokens(expires_at);
CREATE INDEX idx_blacklisted_tokens_user ON blacklisted_tokens(user_id, token_type);
```

### Migration 4: Audit Logging System
```sql
-- Comprehensive security audit logging
CREATE TABLE security_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR REFERENCES users(id),
    session_id UUID REFERENCES user_sessions(id),
    event_type VARCHAR(50) NOT NULL,
    event_category VARCHAR(20) NOT NULL CHECK (
        event_category IN ('auth', 'mfa', 'password', 'oauth', 'admin', 'security')
    ),
    event_data JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    location_info JSONB DEFAULT '{}',
    success BOOLEAN NOT NULL,
    error_code VARCHAR(50),
    error_message TEXT,
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Event types enum for reference
COMMENT ON COLUMN security_audit_logs.event_type IS 
'Possible values: login, logout, register, mfa_setup, mfa_verify, mfa_disable, 
password_change, password_reset, oauth_authorize, oauth_callback, token_refresh, 
session_terminate, account_lock, account_unlock, role_assign, role_remove, 
admin_action, suspicious_activity';

-- Performance indexes
CREATE INDEX idx_audit_logs_user_time ON security_audit_logs(user_id, created_at);
CREATE INDEX idx_audit_logs_event_time ON security_audit_logs(event_type, created_at);
CREATE INDEX idx_audit_logs_category_time ON security_audit_logs(event_category, created_at);
CREATE INDEX idx_audit_logs_success ON security_audit_logs(success, created_at);
CREATE INDEX idx_audit_logs_ip ON security_audit_logs(ip_address, created_at);

-- Partitioning for performance (PostgreSQL 12+)
ALTER TABLE security_audit_logs 
PARTITION BY RANGE (created_at);

-- Create monthly partitions
CREATE TABLE security_audit_logs_202501 
PARTITION OF security_audit_logs
FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
```

### Migration 5: Role-Based Access Control
```sql
-- Roles and permissions system
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system_role BOOLEAN DEFAULT FALSE, -- Prevent deletion of system roles
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR REFERENCES users(id),
    
    CONSTRAINT valid_role_name CHECK (name ~ '^[a-zA-Z_][a-zA-Z0-9_]*$')
);

-- User role assignments
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE, -- Optional role expiration
    granted_by VARCHAR NOT NULL REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE,
    
    CONSTRAINT unique_user_role UNIQUE (user_id, role_id),
    CONSTRAINT valid_expiry CHECK (expires_at IS NULL OR expires_at > granted_at)
);

-- Permission groups for easier management
CREATE TABLE permission_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_user_roles_user_active ON user_roles(user_id, is_active);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- Insert default roles
INSERT INTO roles (name, description, permissions, is_system_role) VALUES
('super_admin', 'System administrator with full access', 
 '["*"]', TRUE),
('admin', 'Application administrator', 
 '["user.*", "role.*", "audit.*", "system.read"]', TRUE),
('user', 'Standard user with basic permissions', 
 '["task.*", "profile.*", "oauth.*"]', TRUE),
('viewer', 'Read-only access', 
 '["task.read", "profile.read"]', TRUE);
```

### Migration 6: OAuth Security Enhancement
```sql
-- OAuth state and PKCE tracking
CREATE TABLE oauth_states (
    state VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR NOT NULL REFERENCES users(id),
    provider VARCHAR(50) NOT NULL,
    code_verifier VARCHAR(128), -- PKCE code verifier
    code_challenge VARCHAR(128), -- PKCE code challenge
    challenge_method VARCHAR(10) DEFAULT 'S256', -- PKCE challenge method
    scopes TEXT[], -- Requested scopes
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_challenge_method CHECK (challenge_method IN ('S256', 'plain')),
    CONSTRAINT valid_expiry CHECK (expires_at > created_at)
);

-- OAuth provider configurations
CREATE TABLE oauth_provider_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_name VARCHAR(50) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    authorization_url TEXT NOT NULL,
    token_url TEXT NOT NULL,
    user_info_url TEXT,
    scopes TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enhanced user integrations with better tracking
ALTER TABLE user_integrations 
ADD COLUMN provider_user_id VARCHAR(255),
ADD COLUMN scopes_granted TEXT[],
ADD COLUMN consent_given_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN last_token_refresh TIMESTAMP WITH TIME ZONE,
ADD COLUMN integration_status VARCHAR(20) DEFAULT 'active' CHECK (
    integration_status IN ('active', 'revoked', 'expired', 'error')
);

-- Indexes
CREATE INDEX idx_oauth_states_expires ON oauth_states(expires_at);
CREATE INDEX idx_oauth_states_user ON oauth_states(user_id, provider);
CREATE INDEX idx_integrations_status ON user_integrations(integration_status);
```

### Migration 7: Rate Limiting & Security
```sql
-- Rate limiting tracking (complement to Redis)
CREATE TABLE rate_limit_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier VARCHAR(255) NOT NULL, -- IP, user_id, or composite key
    endpoint VARCHAR(100) NOT NULL,
    limit_type VARCHAR(50) NOT NULL, -- 'ip', 'user', 'global'
    attempts INTEGER NOT NULL,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    window_end TIMESTAMP WITH TIME ZONE NOT NULL,
    blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security incidents tracking
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    user_id VARCHAR REFERENCES users(id),
    ip_address INET,
    description TEXT NOT NULL,
    details JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive')),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- IP allowlist/blocklist
CREATE TABLE ip_access_control (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    ip_range CIDR, -- For CIDR notation ranges
    action VARCHAR(10) NOT NULL CHECK (action IN ('allow', 'block')),
    reason TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT ip_or_range CHECK ((ip_address IS NOT NULL) OR (ip_range IS NOT NULL))
);

-- Indexes
CREATE INDEX idx_rate_violations_identifier ON rate_limit_violations(identifier, endpoint);
CREATE INDEX idx_rate_violations_window ON rate_limit_violations(window_start, window_end);
CREATE INDEX idx_security_incidents_severity ON security_incidents(severity, status, created_at);
CREATE INDEX idx_ip_access_control_ip ON ip_access_control(ip_address) WHERE expires_at IS NULL OR expires_at > NOW();
```

### Migration 8: Data Retention & Cleanup
```sql
-- Data retention policies
CREATE TABLE data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL,
    retention_days INTEGER NOT NULL,
    cleanup_field VARCHAR(50) NOT NULL, -- Field to check for cleanup
    is_active BOOLEAN DEFAULT TRUE,
    last_cleanup_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default retention policies
INSERT INTO data_retention_policies (table_name, retention_days, cleanup_field) VALUES
('security_audit_logs', 2555, 'created_at'), -- 7 years for compliance
('rate_limit_violations', 90, 'created_at'),
('oauth_states', 1, 'expires_at'),
('blacklisted_tokens', 1, 'expires_at'),
('user_sessions', 30, 'expires_at'); -- Keep for 30 days after expiry

-- Cleanup stored procedures
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS INTEGER AS $$
DECLARE
    policy RECORD;
    cleanup_count INTEGER := 0;
    total_cleaned INTEGER := 0;
BEGIN
    FOR policy IN SELECT * FROM data_retention_policies WHERE is_active = TRUE
    LOOP
        EXECUTE format('DELETE FROM %I WHERE %I < NOW() - INTERVAL ''%s days''', 
                      policy.table_name, 
                      policy.cleanup_field, 
                      policy.retention_days);
        
        GET DIAGNOSTICS cleanup_count = ROW_COUNT;
        total_cleaned := total_cleaned + cleanup_count;
        
        UPDATE data_retention_policies 
        SET last_cleanup_at = NOW() 
        WHERE id = policy.id;
        
        RAISE NOTICE 'Cleaned % records from %', cleanup_count, policy.table_name;
    END LOOP;
    
    RETURN total_cleaned;
END;
$$ LANGUAGE plpgsql;
```

## Migration Execution Strategy

### 1. Pre-Migration Checks
```sql
-- Verify data integrity before migrations
SELECT 'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'user_integrations', COUNT(*) FROM user_integrations;

-- Check for potential conflicts
SELECT email, COUNT(*) 
FROM users 
GROUP BY email 
HAVING COUNT(*) > 1;
```

### 2. Migration Order
```bash
# Execute migrations in order
alembic revision --autogenerate -m "Add user security columns"
alembic revision --autogenerate -m "Add MFA support tables"
alembic revision --autogenerate -m "Add session management"
alembic revision --autogenerate -m "Add audit logging system"
alembic revision --autogenerate -m "Add RBAC system"
alembic revision --autogenerate -m "Enhanced OAuth security"
alembic revision --autogenerate -m "Rate limiting and security"
alembic revision --autogenerate -m "Data retention policies"

# Apply migrations
alembic upgrade head
```

### 3. Data Migration Scripts
```python
# Populate default data after schema creation
async def populate_default_data():
    """Populate default roles, permissions, and configurations"""
    
    # Default permissions
    permissions = {
        "task.create", "task.read", "task.update", "task.delete",
        "profile.read", "profile.update", "profile.delete",
        "oauth.connect", "oauth.disconnect",
        "mfa.setup", "mfa.disable",
        "user.create", "user.read", "user.update", "user.delete",
        "role.create", "role.read", "role.update", "role.delete",
        "audit.read", "system.read", "system.write"
    }
    
    # Create default OAuth provider configs
    providers = [
        {
            "provider_name": "microsoft",
            "client_id": os.getenv("MICROSOFT_CLIENT_ID"),
            "authorization_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "user_info_url": "https://graph.microsoft.com/v1.0/me",
            "scopes": ["openid", "profile", "email", "Tasks.ReadWrite"]
        },
        {
            "provider_name": "notion",
            "client_id": os.getenv("NOTION_CLIENT_ID"),
            "authorization_url": "https://api.notion.com/v1/oauth/authorize",
            "token_url": "https://api.notion.com/v1/oauth/token",
            "user_info_url": "https://api.notion.com/v1/users/me",
            "scopes": []
        }
    ]
```

### 4. Performance Optimization
```sql
-- Analyze tables after migration
ANALYZE users, user_sessions, security_audit_logs, user_roles;

-- Create additional indexes based on query patterns
CREATE INDEX CONCURRENTLY idx_audit_logs_composite 
ON security_audit_logs (user_id, event_category, created_at DESC);

-- Vacuum and reindex
VACUUM ANALYZE;
REINDEX DATABASE ultimate_planner;
```

### 5. Rollback Strategy
```sql
-- Create rollback scripts for each migration
-- Store original data before destructive changes
CREATE TABLE migration_rollback_data AS 
SELECT table_name, row_data::jsonb, operation, created_at
FROM audit_table;

-- Test rollback procedures
BEGIN;
-- Rollback commands here
ROLLBACK; -- Test only, don't commit
```

This comprehensive database schema evolution plan ensures a smooth transition to enterprise-grade authentication while maintaining data integrity and system availability.