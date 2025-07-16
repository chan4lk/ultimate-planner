from sqlalchemy import Column, String, Text, DateTime, Integer, Boolean, Enum as SQLEnum, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from .base import Base


class TaskStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class TaskSource(str, Enum):
    MANUAL = "manual"
    MICROSOFT_TEAMS = "microsoft_teams"
    MICROSOFT_PLANNER = "microsoft_planner"
    NOTION = "notion"
    EXCEL_IMPORT = "excel_import"


class UnifiedTask(Base):
    __tablename__ = "unified_tasks"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    due_date = Column(DateTime, nullable=True)
    status = Column(SQLEnum(TaskStatus), nullable=False, default=TaskStatus.NOT_STARTED)
    priority = Column(Integer, nullable=True)
    source = Column(SQLEnum(TaskSource), nullable=False)
    source_id = Column(String, nullable=False)  # Original ID from source platform
    source_url = Column(String, nullable=True)
    tags = Column(JSON, nullable=True, default=list)  # List of strings
    assignee = Column(String, nullable=True)
    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(DateTime, nullable=False, default=func.now(), onupdate=func.now())
    synced_at = Column(DateTime, nullable=False, default=func.now())

    # Relationships
    parent_dependencies = relationship(
        "TaskDependency",
        foreign_keys="TaskDependency.child_task_id",
        back_populates="child_task"
    )
    child_dependencies = relationship(
        "TaskDependency",
        foreign_keys="TaskDependency.parent_task_id",
        back_populates="parent_task"
    )

    def __repr__(self):
        return f"<UnifiedTask(id='{self.id}', title='{self.title}', status='{self.status}')>"

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for API responses"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "description": self.description,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "status": self.status.value,
            "priority": self.priority,
            "source": self.source.value,
            "source_id": self.source_id,
            "source_url": self.source_url,
            "tags": self.tags or [],
            "assignee": self.assignee,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "synced_at": self.synced_at.isoformat()
        }