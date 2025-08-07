"""Add session management tables

Revision ID: add_session_management
Revises: previous_revision
Create Date: 2024-01-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'add_session_management'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create user_sessions table
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('device_fingerprint', sa.String(32), nullable=False),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('device_type', sa.String(20)),
        sa.Column('os', sa.String(50)),
        sa.Column('browser', sa.String(50)),
        sa.Column('jwt_token_hash', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_activity', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True)),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('remember_me', sa.Boolean(), default=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True)),
        sa.Column('revoked_by', sa.String(), sa.ForeignKey('users.id')),
        sa.Column('login_attempts', sa.Integer(), default=0),
        sa.Column('suspicious_activity_count', sa.Integer(), default=0),
        sa.Column('last_security_check', sa.DateTime(timezone=True)),
        sa.Column('risk_score', sa.String(10), default='low'),
    )
    
    # Create security_events table
    op.create_table(
        'security_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.String(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('session_id', sa.String(36), sa.ForeignKey('user_sessions.id')),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('event_description', sa.Text()),
        sa.Column('severity', sa.String(20), default='low'),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('device_fingerprint', sa.String(32)),
        sa.Column('occurred_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('metadata', sa.Text()),
        sa.Column('resolved', sa.Boolean(), default=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True)),
        sa.Column('resolved_by', sa.String(), sa.ForeignKey('users.id')),
    )
    
    # Create indexes for performance
    op.create_index('idx_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('idx_user_sessions_device', 'user_sessions', ['user_id', 'device_fingerprint'])
    op.create_index('idx_user_sessions_active', 'user_sessions', ['user_id', 'is_active'])
    op.create_index('idx_user_sessions_expires', 'user_sessions', ['expires_at'])
    op.create_index('idx_user_sessions_activity', 'user_sessions', ['last_activity'])
    
    op.create_index('idx_security_events_user', 'security_events', ['user_id'])
    op.create_index('idx_security_events_session', 'security_events', ['session_id'])
    op.create_index('idx_security_events_type', 'security_events', ['event_type'])
    op.create_index('idx_security_events_severity', 'security_events', ['severity'])
    op.create_index('idx_security_events_time', 'security_events', ['occurred_at'])
    op.create_index('idx_security_events_unresolved', 'security_events', ['resolved', 'severity'])


def downgrade() -> None:
    # Drop indexes
    op.drop_index('idx_security_events_unresolved')
    op.drop_index('idx_security_events_time')
    op.drop_index('idx_security_events_severity')
    op.drop_index('idx_security_events_type')
    op.drop_index('idx_security_events_session')
    op.drop_index('idx_security_events_user')
    
    op.drop_index('idx_user_sessions_activity')
    op.drop_index('idx_user_sessions_expires')
    op.drop_index('idx_user_sessions_active')
    op.drop_index('idx_user_sessions_device')
    op.drop_index('idx_user_sessions_user_id')
    
    # Drop tables
    op.drop_table('security_events')
    op.drop_table('user_sessions')