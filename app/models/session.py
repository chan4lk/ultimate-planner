"""Session database models for persistent storage (optional)."""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .base import Base


class UserSession(Base):
    """User session model for persistent storage."""
    __tablename__ = "user_sessions"
    
    # Primary key - session ID
    id = Column(String(36), primary_key=True)  # UUID session ID
    
    # Foreign key to user
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Device and network information
    device_fingerprint = Column(String(32), nullable=False)
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    device_type = Column(String(20))  # mobile, desktop, tablet
    os = Column(String(50))
    browser = Column(String(50))
    
    # Session metadata
    jwt_token_hash = Column(String(64), nullable=False)  # SHA256 hash of JWT
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_activity = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True))
    
    # Session status
    is_active = Column(Boolean, default=True)
    remember_me = Column(Boolean, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # Who revoked it
    
    # Security tracking
    login_attempts = Column(Integer, default=0)
    suspicious_activity_count = Column(Integer, default=0)
    last_security_check = Column(DateTime(timezone=True))
    risk_score = Column(String(10), default="low")  # low, medium, high
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="sessions")
    revoked_by_user = relationship("User", foreign_keys=[revoked_by])
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_user_sessions_user_id", "user_id"),
        Index("idx_user_sessions_device", "user_id", "device_fingerprint"),
        Index("idx_user_sessions_active", "user_id", "is_active"),
        Index("idx_user_sessions_expires", "expires_at"),
        Index("idx_user_sessions_activity", "last_activity"),
    )
    
    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id}, active={self.is_active})>"
    
    def to_dict(self):
        """Convert session to dictionary."""
        return {
            "session_id": self.id,
            "user_id": self.user_id,
            "device_fingerprint": self.device_fingerprint,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "device_type": self.device_type,
            "os": self.os,
            "browser": self.browser,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "remember_me": self.remember_me,
            "risk_score": self.risk_score,
            "suspicious_activity_count": self.suspicious_activity_count
        }
    
    def is_expired(self):
        """Check if session is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
    
    def revoke(self, revoked_by_user_id: int = None):
        """Revoke the session."""
        self.is_active = False
        self.revoked_at = datetime.now(timezone.utc)
        if revoked_by_user_id:
            self.revoked_by = revoked_by_user_id


class SecurityEvent(Base):
    """Security events tracking."""
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_id = Column(String(36), ForeignKey("user_sessions.id"), nullable=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)  # login, logout, token_refresh, suspicious_activity
    event_description = Column(Text)
    severity = Column(String(20), default="low")  # low, medium, high, critical
    
    # Context information
    ip_address = Column(String(45))
    user_agent = Column(Text)
    device_fingerprint = Column(String(32))
    
    # Timing
    occurred_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    # Additional metadata
    metadata = Column(Text)  # JSON string for additional event data
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True))
    resolved_by = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    session = relationship("UserSession", backref="security_events")
    resolver = relationship("User", foreign_keys=[resolved_by])
    
    # Indexes
    __table_args__ = (
        Index("idx_security_events_user", "user_id"),
        Index("idx_security_events_session", "session_id"),
        Index("idx_security_events_type", "event_type"),
        Index("idx_security_events_severity", "severity"),
        Index("idx_security_events_time", "occurred_at"),
        Index("idx_security_events_unresolved", "resolved", "severity"),
    )
    
    def __repr__(self):
        return f"<SecurityEvent(id={self.id}, type={self.event_type}, user_id={self.user_id})>"