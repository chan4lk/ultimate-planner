"""MFA (Multi-Factor Authentication) database models."""
from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, Integer
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base
import uuid


class UserMFASecret(Base):
    """User MFA secrets and configuration."""
    __tablename__ = "user_mfa_secrets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    secret_key = Column(String, nullable=False)  # Encrypted TOTP secret
    backup_codes = Column(Text, nullable=True)   # Encrypted backup codes (JSON)
    is_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationship
    user = relationship("User", back_populates="mfa_secret")

    def __repr__(self):
        return f"<UserMFASecret(id={self.id}, user_id={self.user_id}, enabled={self.is_enabled})>"


class UserMFAAttempt(Base):
    """MFA verification attempts for rate limiting and audit."""
    __tablename__ = "user_mfa_attempts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    attempt_type = Column(String, nullable=False)  # 'totp' or 'backup_code'
    success = Column(Boolean, default=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship
    user = relationship("User")

    def __repr__(self):
        return f"<UserMFAAttempt(id={self.id}, user_id={self.user_id}, type={self.attempt_type}, success={self.success})>"