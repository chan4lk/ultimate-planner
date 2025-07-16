import pytest
import os
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.base import Base


@pytest.fixture(scope="function")
def test_db():
    """Create a temporary database for testing"""
    # Create a temporary file for the test database
    db_fd, db_path = tempfile.mkstemp()
    test_database_url = f"sqlite:///{db_path}"
    
    # Create test engine and session
    engine = create_engine(test_database_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create a session for the test
    session = TestingSessionLocal()
    
    yield session
    
    # Cleanup
    session.close()
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def sample_user_id():
    """Provide a sample user ID for testing"""
    return "test-user-123"