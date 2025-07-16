import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from app.models.unified_task import UnifiedTask, TaskStatus, TaskSource
from app.models.user_integration import UserIntegration, SyncStatus
from app.models.task_dependency import TaskDependency, DependencyType


class TestUnifiedTask:
    """Test cases for UnifiedTask model"""
    
    def test_create_unified_task(self, test_db, sample_user_id):
        """Test creating a basic unified task"""
        task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Test Task",
            description="This is a test task",
            status=TaskStatus.NOT_STARTED,
            source=TaskSource.MANUAL,
            source_id="manual-1"
        )
        
        test_db.add(task)
        test_db.commit()
        
        # Verify task was created
        retrieved_task = test_db.query(UnifiedTask).filter(UnifiedTask.id == task.id).first()
        assert retrieved_task is not None
        assert retrieved_task.title == "Test Task"
        assert retrieved_task.status == TaskStatus.NOT_STARTED
        assert retrieved_task.source == TaskSource.MANUAL
        assert retrieved_task.user_id == sample_user_id
    
    def test_unified_task_with_due_date(self, test_db, sample_user_id):
        """Test creating a task with due date"""
        due_date = datetime.now() + timedelta(days=7)
        task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Task with Due Date",
            due_date=due_date,
            status=TaskStatus.NOT_STARTED,
            source=TaskSource.MICROSOFT_PLANNER,
            source_id="planner-123"
        )
        
        test_db.add(task)
        test_db.commit()
        
        retrieved_task = test_db.query(UnifiedTask).filter(UnifiedTask.id == task.id).first()
        assert retrieved_task.due_date == due_date
    
    def test_unified_task_with_tags(self, test_db, sample_user_id):
        """Test creating a task with tags"""
        tags = ["urgent", "project-alpha", "development"]
        task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Task with Tags",
            tags=tags,
            status=TaskStatus.IN_PROGRESS,
            source=TaskSource.NOTION,
            source_id="notion-456"
        )
        
        test_db.add(task)
        test_db.commit()
        
        retrieved_task = test_db.query(UnifiedTask).filter(UnifiedTask.id == task.id).first()
        assert retrieved_task.tags == tags
    
    def test_unified_task_to_dict(self, test_db, sample_user_id):
        """Test converting task to dictionary"""
        task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Test Task",
            description="Test description",
            status=TaskStatus.COMPLETED,
            priority=1,
            source=TaskSource.EXCEL_IMPORT,
            source_id="excel-789",
            tags=["test", "example"]
        )
        
        test_db.add(task)
        test_db.commit()
        
        task_dict = task.to_dict()
        assert task_dict["id"] == task.id
        assert task_dict["title"] == "Test Task"
        assert task_dict["status"] == "completed"
        assert task_dict["source"] == "excel_import"
        assert task_dict["tags"] == ["test", "example"]
    
    def test_task_status_enum_values(self):
        """Test TaskStatus enum values"""
        assert TaskStatus.NOT_STARTED.value == "not_started"
        assert TaskStatus.IN_PROGRESS.value == "in_progress"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.CANCELLED.value == "cancelled"
    
    def test_task_source_enum_values(self):
        """Test TaskSource enum values"""
        assert TaskSource.MANUAL.value == "manual"
        assert TaskSource.MICROSOFT_TEAMS.value == "microsoft_teams"
        assert TaskSource.MICROSOFT_PLANNER.value == "microsoft_planner"
        assert TaskSource.NOTION.value == "notion"
        assert TaskSource.EXCEL_IMPORT.value == "excel_import"


class TestUserIntegration:
    """Test cases for UserIntegration model"""
    
    def test_create_user_integration(self, test_db, sample_user_id):
        """Test creating a basic user integration"""
        integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.MICROSOFT_TEAMS.value,
            is_active=True,
            sync_frequency=timedelta(minutes=30),
            sync_status=SyncStatus.ACTIVE.value
        )
        
        test_db.add(integration)
        test_db.commit()
        
        retrieved_integration = test_db.query(UserIntegration).filter(
            UserIntegration.id == integration.id
        ).first()
        assert retrieved_integration is not None
        assert retrieved_integration.source == "microsoft_teams"
        assert retrieved_integration.is_active is True
        assert retrieved_integration.sync_frequency == timedelta(minutes=30)
    
    def test_user_integration_with_tokens(self, test_db, sample_user_id):
        """Test creating integration with authentication tokens"""
        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.NOTION.value,
            auth_token="encrypted_token_123",
            refresh_token="encrypted_refresh_456",
            token_expires_at=expires_at,
            sync_status=SyncStatus.ACTIVE.value
        )
        
        test_db.add(integration)
        test_db.commit()
        
        retrieved_integration = test_db.query(UserIntegration).filter(
            UserIntegration.id == integration.id
        ).first()
        assert retrieved_integration.auth_token == "encrypted_token_123"
        assert retrieved_integration.refresh_token == "encrypted_refresh_456"
        assert retrieved_integration.token_expires_at == expires_at
    
    def test_user_integration_configuration(self, test_db, sample_user_id):
        """Test integration with custom configuration"""
        config = {
            "database_id": "notion-db-123",
            "sync_completed_tasks": False,
            "custom_field_mapping": {"priority": "Priority"}
        }
        
        integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.NOTION.value,
            configuration=config,
            sync_status=SyncStatus.PENDING.value
        )
        
        test_db.add(integration)
        test_db.commit()
        
        retrieved_integration = test_db.query(UserIntegration).filter(
            UserIntegration.id == integration.id
        ).first()
        assert retrieved_integration.configuration == config
    
    def test_is_token_expired(self, test_db, sample_user_id):
        """Test token expiration check"""
        # Test expired token
        expired_integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.MICROSOFT_PLANNER.value,
            token_expires_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1),
            sync_status=SyncStatus.ERROR.value
        )
        assert expired_integration.is_token_expired() is True
        
        # Test valid token
        valid_integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.MICROSOFT_PLANNER.value,
            token_expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1),
            sync_status=SyncStatus.ACTIVE.value
        )
        assert valid_integration.is_token_expired() is False
        
        # Test no expiration date
        no_expiry_integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.MANUAL.value,
            sync_status=SyncStatus.ACTIVE.value
        )
        assert no_expiry_integration.is_token_expired() is False
    
    def test_needs_sync(self, test_db, sample_user_id):
        """Test sync requirement check"""
        # Test integration that needs sync (never synced)
        never_synced = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.NOTION.value,
            is_active=True,
            sync_status=SyncStatus.ACTIVE.value,
            sync_frequency=timedelta(minutes=15)
        )
        assert never_synced.needs_sync() is True
        
        # Test integration that doesn't need sync (recently synced)
        recently_synced = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.NOTION.value,
            is_active=True,
            sync_status=SyncStatus.ACTIVE.value,
            sync_frequency=timedelta(minutes=15),
            last_sync_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
        )
        assert recently_synced.needs_sync() is False
        
        # Test inactive integration
        inactive_integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.NOTION.value,
            is_active=False,
            sync_status=SyncStatus.DISABLED.value
        )
        assert inactive_integration.needs_sync() is False


class TestTaskDependency:
    """Test cases for TaskDependency model"""
    
    def test_create_task_dependency(self, test_db, sample_user_id):
        """Test creating a task dependency"""
        # Create parent and child tasks first
        parent_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Parent Task",
            status=TaskStatus.IN_PROGRESS,
            source=TaskSource.MANUAL,
            source_id="parent-1"
        )
        
        child_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Child Task",
            status=TaskStatus.NOT_STARTED,
            source=TaskSource.MANUAL,
            source_id="child-1"
        )
        
        test_db.add(parent_task)
        test_db.add(child_task)
        test_db.commit()
        
        # Create dependency
        dependency = TaskDependency(
            id=str(uuid4()),
            user_id=sample_user_id,
            parent_task_id=parent_task.id,
            child_task_id=child_task.id,
            dependency_type=DependencyType.BLOCKS
        )
        
        test_db.add(dependency)
        test_db.commit()
        
        # Verify dependency was created
        retrieved_dependency = test_db.query(TaskDependency).filter(
            TaskDependency.id == dependency.id
        ).first()
        assert retrieved_dependency is not None
        assert retrieved_dependency.parent_task_id == parent_task.id
        assert retrieved_dependency.child_task_id == child_task.id
        assert retrieved_dependency.dependency_type == DependencyType.BLOCKS
    
    def test_task_dependency_relationships(self, test_db, sample_user_id):
        """Test task dependency relationships"""
        # Create tasks
        parent_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Parent Task",
            status=TaskStatus.COMPLETED,
            source=TaskSource.MANUAL,
            source_id="parent-2"
        )
        
        child_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Child Task",
            status=TaskStatus.NOT_STARTED,
            source=TaskSource.MANUAL,
            source_id="child-2"
        )
        
        test_db.add(parent_task)
        test_db.add(child_task)
        test_db.commit()
        
        # Create subtask dependency
        dependency = TaskDependency(
            id=str(uuid4()),
            user_id=sample_user_id,
            parent_task_id=parent_task.id,
            child_task_id=child_task.id,
            dependency_type=DependencyType.SUBTASK
        )
        
        test_db.add(dependency)
        test_db.commit()
        
        # Test relationships
        retrieved_parent = test_db.query(UnifiedTask).filter(
            UnifiedTask.id == parent_task.id
        ).first()
        retrieved_child = test_db.query(UnifiedTask).filter(
            UnifiedTask.id == child_task.id
        ).first()
        
        # Check parent has child dependencies
        assert len(retrieved_parent.child_dependencies) == 1
        assert retrieved_parent.child_dependencies[0].child_task_id == child_task.id
        
        # Check child has parent dependencies
        assert len(retrieved_child.parent_dependencies) == 1
        assert retrieved_child.parent_dependencies[0].parent_task_id == parent_task.id
    
    def test_dependency_type_enum_values(self):
        """Test DependencyType enum values"""
        assert DependencyType.BLOCKS.value == "blocks"
        assert DependencyType.SUBTASK.value == "subtask"
        assert DependencyType.RELATED.value == "related"
    
    def test_task_dependency_to_dict(self, test_db, sample_user_id):
        """Test converting dependency to dictionary"""
        # Create tasks
        parent_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Parent Task",
            status=TaskStatus.IN_PROGRESS,
            source=TaskSource.MANUAL,
            source_id="parent-3"
        )
        
        child_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Child Task",
            status=TaskStatus.NOT_STARTED,
            source=TaskSource.MANUAL,
            source_id="child-3"
        )
        
        test_db.add(parent_task)
        test_db.add(child_task)
        test_db.commit()
        
        dependency = TaskDependency(
            id=str(uuid4()),
            user_id=sample_user_id,
            parent_task_id=parent_task.id,
            child_task_id=child_task.id,
            dependency_type=DependencyType.RELATED
        )
        
        test_db.add(dependency)
        test_db.commit()
        
        dependency_dict = dependency.to_dict()
        assert dependency_dict["id"] == dependency.id
        assert dependency_dict["user_id"] == sample_user_id
        assert dependency_dict["parent_task_id"] == parent_task.id
        assert dependency_dict["child_task_id"] == child_task.id
        assert dependency_dict["dependency_type"] == "related"


class TestModelIntegration:
    """Test cases for model integration and complex scenarios"""
    
    def test_user_with_multiple_integrations_and_tasks(self, test_db, sample_user_id):
        """Test a user with multiple integrations and tasks"""
        # Create multiple integrations
        teams_integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.MICROSOFT_TEAMS.value,
            is_active=True,
            sync_status=SyncStatus.ACTIVE.value
        )
        
        notion_integration = UserIntegration(
            id=str(uuid4()),
            user_id=sample_user_id,
            source=TaskSource.NOTION.value,
            is_active=True,
            sync_status=SyncStatus.ACTIVE.value
        )
        
        test_db.add(teams_integration)
        test_db.add(notion_integration)
        
        # Create tasks from different sources
        teams_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Teams Task",
            source=TaskSource.MICROSOFT_TEAMS,
            source_id="teams-123",
            status=TaskStatus.IN_PROGRESS
        )
        
        notion_task = UnifiedTask(
            id=str(uuid4()),
            user_id=sample_user_id,
            title="Notion Task",
            source=TaskSource.NOTION,
            source_id="notion-456",
            status=TaskStatus.NOT_STARTED
        )
        
        test_db.add(teams_task)
        test_db.add(notion_task)
        test_db.commit()
        
        # Verify all data was created correctly
        user_integrations = test_db.query(UserIntegration).filter(
            UserIntegration.user_id == sample_user_id
        ).all()
        assert len(user_integrations) == 2
        
        user_tasks = test_db.query(UnifiedTask).filter(
            UnifiedTask.user_id == sample_user_id
        ).all()
        assert len(user_tasks) == 2
        
        # Verify tasks from different sources
        teams_tasks = [t for t in user_tasks if t.source == TaskSource.MICROSOFT_TEAMS]
        notion_tasks = [t for t in user_tasks if t.source == TaskSource.NOTION]
        assert len(teams_tasks) == 1
        assert len(notion_tasks) == 1