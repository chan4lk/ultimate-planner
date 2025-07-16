import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.database import get_db
from app.models.base import Base
from app.models.user import User
from app.auth.security import get_password_hash, verify_password, create_access_token, verify_token
from app.auth.service import AuthService
from app.auth.schemas import UserCreate, UserLogin
import tempfile
import os


# Create test database
@pytest.fixture
def test_db():
    # Create temporary database file
    db_fd, db_path = tempfile.mkstemp()
    database_url = f"sqlite:///{db_path}"
    
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    def override_get_db():
        try:
            db = TestingSessionLocal()
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    
    yield TestingSessionLocal()
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)
    app.dependency_overrides.clear()


@pytest.fixture
def client(test_db):
    # The test_db fixture sets up the database override
    return TestClient(app)


class TestPasswordSecurity:
    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert verify_password(password, hashed) is True
        assert verify_password("wrongpassword", hashed) is False

    def test_password_hash_uniqueness(self):
        """Test that same password generates different hashes."""
        password = "testpassword123"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        assert hash1 != hash2
        assert verify_password(password, hash1) is True
        assert verify_password(password, hash2) is True


class TestJWTTokens:
    def test_token_creation_and_verification(self):
        """Test JWT token creation and verification."""
        data = {"sub": "user123", "email": "test@example.com"}
        token = create_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        
        payload = verify_token(token)
        assert payload is not None
        assert payload["sub"] == "user123"
        assert payload["email"] == "test@example.com"
        assert "exp" in payload

    def test_invalid_token_verification(self):
        """Test verification of invalid tokens."""
        invalid_token = "invalid.token.here"
        payload = verify_token(invalid_token)
        assert payload is None

    def test_expired_token(self):
        """Test handling of expired tokens."""
        from datetime import timedelta
        data = {"sub": "user123"}
        # Create token that expires immediately
        token = create_access_token(data, expires_delta=timedelta(seconds=-1))
        
        payload = verify_token(token)
        assert payload is None

    def test_token_blacklisting(self):
        """Test token blacklisting functionality."""
        from app.auth.security import blacklist_token, is_token_blacklisted, clear_token_blacklist
        
        # Clear blacklist first
        clear_token_blacklist()
        
        data = {"sub": "user123"}
        token = create_access_token(data)
        
        # Token should be valid initially
        payload = verify_token(token)
        assert payload is not None
        assert not is_token_blacklisted(token)
        
        # Blacklist the token
        blacklist_token(token)
        assert is_token_blacklisted(token)
        
        # Token should now be invalid
        payload = verify_token(token)
        assert payload is None


class TestDataEncryption:
    def test_encrypt_decrypt_sensitive_data(self):
        """Test encryption and decryption of sensitive data."""
        from app.auth.security import encrypt_sensitive_data, decrypt_sensitive_data
        
        original_data = "sensitive-api-token-12345"
        
        # Encrypt the data
        encrypted_data = encrypt_sensitive_data(original_data)
        
        # Encrypted data should be different from original
        assert encrypted_data != original_data
        assert len(encrypted_data) > len(original_data)
        
        # Decrypt the data
        decrypted_data = decrypt_sensitive_data(encrypted_data)
        
        # Decrypted data should match original
        assert decrypted_data == original_data

    def test_encrypt_empty_string(self):
        """Test encryption of empty string."""
        from app.auth.security import encrypt_sensitive_data, decrypt_sensitive_data
        
        empty_string = ""
        encrypted = encrypt_sensitive_data(empty_string)
        decrypted = decrypt_sensitive_data(encrypted)
        
        assert encrypted == empty_string
        assert decrypted == empty_string

    def test_decrypt_invalid_data(self):
        """Test decryption of invalid data."""
        from app.auth.security import decrypt_sensitive_data
        
        invalid_data = "invalid-encrypted-data"
        result = decrypt_sensitive_data(invalid_data)
        
        # Should return empty string for invalid data
        assert result == ""


class TestInputValidation:
    def test_password_validation_too_short(self, client):
        """Test password validation for too short password."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "short"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "at least 8 characters" in error_detail["msg"]

    def test_password_validation_no_uppercase(self, client):
        """Test password validation for missing uppercase letter."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "lowercase123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "uppercase letter" in error_detail["msg"]

    def test_password_validation_no_lowercase(self, client):
        """Test password validation for missing lowercase letter."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "UPPERCASE123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "lowercase letter" in error_detail["msg"]

    def test_password_validation_no_digit(self, client):
        """Test password validation for missing digit."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "NoDigitsHere"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "digit" in error_detail["msg"]

    def test_username_validation_too_short(self, client):
        """Test username validation for too short username."""
        user_data = {
            "email": "test@example.com",
            "username": "ab",
            "password": "ValidPass123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "at least 3 characters" in error_detail["msg"]

    def test_username_validation_too_long(self, client):
        """Test username validation for too long username."""
        user_data = {
            "email": "test@example.com",
            "username": "a" * 51,  # 51 characters
            "password": "ValidPass123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "no more than 50 characters" in error_detail["msg"]

    def test_username_validation_invalid_characters(self, client):
        """Test username validation for invalid characters."""
        user_data = {
            "email": "test@example.com",
            "username": "test@user",  # @ is not allowed
            "password": "ValidPass123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422
        error_detail = response.json()["detail"][0]
        assert "letters, numbers, hyphens, and underscores" in error_detail["msg"]

    def test_valid_user_creation(self, client):
        """Test successful user creation with valid data."""
        user_data = {
            "email": "test@example.com",
            "username": "valid_user-123",
            "password": "ValidPass123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["username"] == "valid_user-123"


class TestAuthService:
    def test_create_user(self, test_db):
        """Test user creation."""
        auth_service = AuthService(test_db)
        user_data = UserCreate(
            email="test@example.com",
            username="testuser",
            password="TestPassword123"
        )
        
        user = auth_service.create_user(user_data)
        
        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.username == "testuser"
        assert user.hashed_password != "testpassword123"
        assert user.is_active is True
        assert user.created_at is not None

    def test_create_duplicate_email(self, test_db):
        """Test creating user with duplicate email."""
        auth_service = AuthService(test_db)
        user_data1 = UserCreate(
            email="test@example.com",
            username="testuser1",
            password="TestPassword123"
        )
        user_data2 = UserCreate(
            email="test@example.com",
            username="testuser2",
            password="TestPassword456"
        )
        
        auth_service.create_user(user_data1)
        
        with pytest.raises(Exception) as exc_info:
            auth_service.create_user(user_data2)
        assert "Email already registered" in str(exc_info.value)

    def test_create_duplicate_username(self, test_db):
        """Test creating user with duplicate username."""
        auth_service = AuthService(test_db)
        user_data1 = UserCreate(
            email="test1@example.com",
            username="testuser",
            password="TestPassword123"
        )
        user_data2 = UserCreate(
            email="test2@example.com",
            username="testuser",
            password="TestPassword456"
        )
        
        auth_service.create_user(user_data1)
        
        with pytest.raises(Exception) as exc_info:
            auth_service.create_user(user_data2)
        assert "Username already taken" in str(exc_info.value)

    def test_authenticate_user_success(self, test_db):
        """Test successful user authentication."""
        auth_service = AuthService(test_db)
        user_data = UserCreate(
            email="test@example.com",
            username="testuser",
            password="TestPassword123"
        )
        
        created_user = auth_service.create_user(user_data)
        
        login_data = UserLogin(
            email="test@example.com",
            password="TestPassword123"
        )
        
        authenticated_user = auth_service.authenticate_user(login_data)
        
        assert authenticated_user is not None
        assert authenticated_user.id == created_user.id
        assert authenticated_user.email == "test@example.com"

    def test_authenticate_user_wrong_password(self, test_db):
        """Test authentication with wrong password."""
        auth_service = AuthService(test_db)
        user_data = UserCreate(
            email="test@example.com",
            username="testuser",
            password="TestPassword123"
        )
        
        auth_service.create_user(user_data)
        
        login_data = UserLogin(
            email="test@example.com",
            password="wrongpassword"
        )
        
        authenticated_user = auth_service.authenticate_user(login_data)
        assert authenticated_user is None

    def test_authenticate_nonexistent_user(self, test_db):
        """Test authentication with nonexistent user."""
        auth_service = AuthService(test_db)
        login_data = UserLogin(
            email="nonexistent@example.com",
            password="testpassword123"
        )
        
        authenticated_user = auth_service.authenticate_user(login_data)
        assert authenticated_user is None

    def test_get_user_by_id(self, test_db):
        """Test getting user by ID."""
        auth_service = AuthService(test_db)
        user_data = UserCreate(
            email="test@example.com",
            username="testuser",
            password="TestPassword123"
        )
        
        created_user = auth_service.create_user(user_data)
        retrieved_user = auth_service.get_user_by_id(created_user.id)
        
        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.email == created_user.email

    def test_get_user_by_email(self, test_db):
        """Test getting user by email."""
        auth_service = AuthService(test_db)
        user_data = UserCreate(
            email="test@example.com",
            username="testuser",
            password="TestPassword123"
        )
        
        created_user = auth_service.create_user(user_data)
        retrieved_user = auth_service.get_user_by_email("test@example.com")
        
        assert retrieved_user is not None
        assert retrieved_user.id == created_user.id
        assert retrieved_user.email == "test@example.com"


class TestAuthEndpoints:
    def test_register_user_success(self, client):
        """Test successful user registration."""
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "TestPassword123"
        }
        
        response = client.post("/auth/register", json=user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["username"] == "testuser"
        assert "id" in data
        assert "password" not in data
        assert "hashed_password" not in data

    def test_register_user_invalid_email(self, client):
        """Test registration with invalid email."""
        user_data = {
            "email": "invalid-email",
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/register", json=user_data)
        assert response.status_code == 422

    def test_login_user_success(self, client):
        """Test successful user login."""
        # First register a user
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "TestPassword123"
        }
        client.post("/auth/register", json=user_data)
        
        # Then login
        login_data = {
            "email": "test@example.com",
            "password": "TestPassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_user_wrong_password(self, client):
        """Test login with wrong password."""
        # First register a user
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "TestPassword123"
        }
        client.post("/auth/register", json=user_data)
        
        # Then try to login with wrong password
        login_data = {
            "email": "test@example.com",
            "password": "wrongpassword"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 401
        assert "Incorrect email or password" in response.json()["detail"]

    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "testpassword123"
        }
        
        response = client.post("/auth/login", json=login_data)
        
        assert response.status_code == 401

    def test_get_current_user_info(self, client):
        """Test getting current user information."""
        # Register and login
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "TestPassword123"
        }
        client.post("/auth/register", json=user_data)
        
        login_response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "TestPassword123"
        })
        token = login_response.json()["access_token"]
        
        # Get user info
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["username"] == "testuser"

    def test_get_current_user_info_invalid_token(self, client):
        """Test getting user info with invalid token."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code == 401

    def test_get_current_user_info_no_token(self, client):
        """Test getting user info without token."""
        response = client.get("/auth/me")
        
        assert response.status_code == 403

    def test_logout_user(self, client):
        """Test user logout."""
        # First register and login
        user_data = {
            "email": "test@example.com",
            "username": "testuser",
            "password": "TestPassword123"
        }
        client.post("/auth/register", json=user_data)
        
        login_response = client.post("/auth/login", json={
            "email": "test@example.com",
            "password": "TestPassword123"
        })
        token = login_response.json()["access_token"]
        
        # Then logout
        response = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "logged out" in data["message"].lower()
        
        # Verify token is invalidated by trying to access protected endpoint
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401