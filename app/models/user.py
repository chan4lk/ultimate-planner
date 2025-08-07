from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .base import Base
import uuid


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    mfa_secret = relationship("UserMFASecret", back_populates="user", uselist=False, cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"
    
    @property
    def has_mfa_enabled(self) -> bool:
        """Check if user has MFA enabled."""
        return self.mfa_secret is not None and self.mfa_secret.is_enabled