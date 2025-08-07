-- Ultimate Planner - Database Initialization Script
-- Creates necessary extensions and initial setup

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create application database if not exists
SELECT 'CREATE DATABASE ultimate_planner'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ultimate_planner');

-- Connect to the application database
\c ultimate_planner;

-- Create application user with necessary permissions
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'app_user') THEN
        CREATE USER app_user WITH PASSWORD 'secure_password_change_me';
    END IF;
END
$$;

-- Grant necessary permissions
GRANT CONNECT ON DATABASE ultimate_planner TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT CREATE ON SCHEMA public TO app_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_user;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO app_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO app_user;

-- Create audit schema for compliance logging
CREATE SCHEMA IF NOT EXISTS audit;
GRANT USAGE ON SCHEMA audit TO app_user;
GRANT CREATE ON SCHEMA audit TO app_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA audit GRANT ALL ON TABLES TO app_user;

-- Create security schema for authentication tables
CREATE SCHEMA IF NOT EXISTS security;
GRANT USAGE ON SCHEMA security TO app_user;
GRANT CREATE ON SCHEMA security TO app_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA security TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA security GRANT ALL ON TABLES TO app_user;

-- Performance tuning settings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET track_activity_query_size = 2048;
ALTER SYSTEM SET pg_stat_statements.track = 'all';
ALTER SYSTEM SET log_statement = 'mod';
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Security settings
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
ALTER SYSTEM SET log_lock_waits = 'on';
ALTER SYSTEM SET deadlock_timeout = '1s';

-- Performance settings
ALTER SYSTEM SET max_connections = 200;
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;

-- Create initial audit log function for trigger-based auditing
CREATE OR REPLACE FUNCTION audit.audit_trigger_function()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        INSERT INTO audit.audit_log (
            table_name,
            operation,
            old_data,
            changed_by,
            changed_at
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            row_to_json(OLD),
            current_user,
            current_timestamp
        );
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit.audit_log (
            table_name,
            operation,
            old_data,
            new_data,
            changed_by,
            changed_at
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            row_to_json(OLD),
            row_to_json(NEW),
            current_user,
            current_timestamp
        );
        RETURN NEW;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit.audit_log (
            table_name,
            operation,
            new_data,
            changed_by,
            changed_at
        ) VALUES (
            TG_TABLE_NAME,
            TG_OP,
            row_to_json(NEW),
            current_user,
            current_timestamp
        );
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.audit_log (
    id BIGSERIAL PRIMARY KEY,
    table_name TEXT NOT NULL,
    operation TEXT NOT NULL,
    old_data JSONB,
    new_data JSONB,
    changed_by TEXT DEFAULT current_user,
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
    client_addr INET DEFAULT inet_client_addr(),
    client_port INTEGER DEFAULT inet_client_port()
);

-- Create indexes for audit log
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit.audit_log(table_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_operation ON audit.audit_log(operation);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_at ON audit.audit_log(changed_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_changed_by ON audit.audit_log(changed_by);
CREATE INDEX IF NOT EXISTS idx_audit_log_client_addr ON audit.audit_log(client_addr);

-- Create function to add audit triggers to tables
CREATE OR REPLACE FUNCTION audit.add_audit_trigger(target_table TEXT)
RETURNS VOID AS $$
BEGIN
    EXECUTE format('
        CREATE TRIGGER audit_trigger
        AFTER INSERT OR UPDATE OR DELETE ON %s
        FOR EACH ROW EXECUTE FUNCTION audit.audit_trigger_function();
    ', target_table);
END;
$$ LANGUAGE plpgsql;

-- Create function to remove audit triggers
CREATE OR REPLACE FUNCTION audit.remove_audit_trigger(target_table TEXT)
RETURNS VOID AS $$
BEGIN
    EXECUTE format('DROP TRIGGER IF EXISTS audit_trigger ON %s;', target_table);
END;
$$ LANGUAGE plpgsql;

-- Create security event log table for real-time security monitoring
CREATE TABLE IF NOT EXISTS security.security_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID DEFAULT uuid_generate_v4(),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    user_id TEXT,
    session_id TEXT,
    ip_address INET,
    user_agent TEXT,
    resource TEXT,
    action TEXT,
    outcome TEXT,
    details JSONB,
    risk_score INTEGER,
    compliance_tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp
);

-- Create indexes for security events
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security.security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security.security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security.security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security.security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security.security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_risk_score ON security.security_events(risk_score);
CREATE INDEX IF NOT EXISTS idx_security_events_compliance ON security.security_events USING GIN(compliance_tags);

-- Create session tracking table
CREATE TABLE IF NOT EXISTS security.active_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    device_fingerprint TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    security_flags JSONB DEFAULT '{}'
);

-- Create indexes for session tracking
CREATE INDEX IF NOT EXISTS idx_active_sessions_user_id ON security.active_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_active_sessions_ip_address ON security.active_sessions(ip_address);
CREATE INDEX IF NOT EXISTS idx_active_sessions_created_at ON security.active_sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_active_sessions_last_activity ON security.active_sessions(last_activity);
CREATE INDEX IF NOT EXISTS idx_active_sessions_expires_at ON security.active_sessions(expires_at);

-- Create rate limiting tracking table
CREATE TABLE IF NOT EXISTS security.rate_limit_violations (
    id BIGSERIAL PRIMARY KEY,
    identifier TEXT NOT NULL,
    limit_type TEXT NOT NULL,
    violation_count INTEGER DEFAULT 1,
    first_violation TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
    last_violation TIMESTAMP WITH TIME ZONE DEFAULT current_timestamp,
    blocked_until TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    user_agent TEXT,
    details JSONB
);

-- Create indexes for rate limiting
CREATE INDEX IF NOT EXISTS idx_rate_limit_identifier ON security.rate_limit_violations(identifier);
CREATE INDEX IF NOT EXISTS idx_rate_limit_type ON security.rate_limit_violations(limit_type);
CREATE INDEX IF NOT EXISTS idx_rate_limit_blocked_until ON security.rate_limit_violations(blocked_until);
CREATE INDEX IF NOT EXISTS idx_rate_limit_ip_address ON security.rate_limit_violations(ip_address);

-- Create function to clean up expired data
CREATE OR REPLACE FUNCTION security.cleanup_expired_data()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
BEGIN
    -- Clean up expired sessions
    DELETE FROM security.active_sessions 
    WHERE expires_at < current_timestamp;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Clean up old rate limit violations (keep 30 days)
    DELETE FROM security.rate_limit_violations 
    WHERE first_violation < current_timestamp - interval '30 days';
    
    -- Clean up old security events (keep based on compliance requirements - 7 years)
    DELETE FROM security.security_events 
    WHERE created_at < current_timestamp - interval '7 years';
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create materialized view for security dashboard
CREATE MATERIALIZED VIEW IF NOT EXISTS security.security_dashboard AS
SELECT 
    date_trunc('hour', created_at) as hour,
    event_type,
    severity,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips,
    AVG(risk_score) as avg_risk_score,
    MAX(risk_score) as max_risk_score
FROM security.security_events
WHERE created_at >= current_timestamp - interval '7 days'
GROUP BY date_trunc('hour', created_at), event_type, severity
ORDER BY hour DESC, event_count DESC;

-- Create index on materialized view
CREATE INDEX IF NOT EXISTS idx_security_dashboard_hour ON security.security_dashboard(hour);

-- Create function to refresh security dashboard
CREATE OR REPLACE FUNCTION security.refresh_security_dashboard()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY security.security_dashboard;
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup function (requires pg_cron extension in production)
-- SELECT cron.schedule('cleanup-expired-data', '0 2 * * *', 'SELECT security.cleanup_expired_data();');
-- SELECT cron.schedule('refresh-dashboard', '*/15 * * * *', 'SELECT security.refresh_security_dashboard();');

COMMIT;