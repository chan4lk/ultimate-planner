from sqlalchemy import Column, String, DateTime, Enum as SQLEnum, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from enum import Enum
from datetime import datetime
from typing import Dict, Any
from .base import Base


class DependencyType(str, Enum):
    BLOCKS = "blocks"  # Parent blocks child
    SUBTASK = "subtask"  # Child is subtask of parent
    RELATED = "related"  # Tasks are related


class TaskDependency(Base):
    __tablename__ = "task_dependencies"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, nullable=False, index=True)
    parent_task_id = Column(String, ForeignKey("unified_tasks.id"), nullable=False)
    child_task_id = Column(String, ForeignKey("unified_tasks.id"), nullable=False)
    dependency_type = Column(SQLEnum(DependencyType), nullable=False, default=DependencyType.BLOCKS)
    created_at = Column(DateTime, nullable=False, default=func.now())

    # Relationships
    parent_task = relationship(
        "UnifiedTask",
        foreign_keys=[parent_task_id],
        back_populates="child_dependencies"
    )
    child_task = relationship(
        "UnifiedTask",
        foreign_keys=[child_task_id],
        back_populates="parent_dependencies"
    )

    def __repr__(self):
        return f"<TaskDependency(id='{self.id}', parent='{self.parent_task_id}', child='{self.child_task_id}', type='{self.dependency_type}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for API responses"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "parent_task_id": self.parent_task_id,
            "child_task_id": self.child_task_id,
            "dependency_type": self.dependency_type.value,
            "created_at": self.created_at.isoformat()
        }