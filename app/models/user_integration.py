from sqlalchemy import Column, String, Boolean, DateTime, JSON, Interval
from sqlalchemy.sql import func
from enum import Enum
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from .base import Base
from .unified_task import TaskSource


class SyncStatus(str, Enum):
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    PENDING = "pending"


class UserIntegration(Base):
    __tablename__ = "user_integrations"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False)  # Using String instead of Enum for flexibility
    is_active = Column(Boolean, nullable=False, default=True)
    auth_token = Column(String, nullable=True)  # Encrypted
    refresh_token = Column(String, nullable=True)  # Encrypted
    token_expires_at = Column(DateTime, nullable=True)
    sync_frequency = Column(Interval, nullable=False, default=timedelta(minutes=15))
    last_sync_at = Column(DateTime, nullable=True)
    sync_status = Column(String, nullable=False, default=SyncStatus.PENDING.value)
    configuration = Column(JSON, nullable=True, default=dict)  # Source-specific settings
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<UserIntegration(id='{self.id}', user_id='{self.user_id}', source='{self.source}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for API responses"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "source": self.source,
            "is_active": self.is_active,
            "token_expires_at": self.token_expires_at.isoformat() if self.token_expires_at else None,
            "sync_frequency": str(self.sync_frequency),
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "sync_status": self.sync_status,
            "configuration": self.configuration or {},
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    def is_token_expired(self) -> bool:
        """Check if the authentication token is expired"""
        if not self.token_expires_at:
            return False
        return datetime.now(timezone.utc).replace(tzinfo=None) >= self.token_expires_at

    def needs_sync(self) -> bool:
        """Check if this integration needs to be synced"""
        if not self.is_active or self.sync_status != SyncStatus.ACTIVE.value:
            return False
        if not self.last_sync_at:
            return True
        return datetime.now(timezone.utc).replace(tzinfo=None) >= (self.last_sync_at + self.sync_frequency)