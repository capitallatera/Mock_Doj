import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, get_db
from app.main import app 
from app.main import router as auth_router 
from app.models.user import User, Organization, Role, PortalPage, RoleDetail
from app.models.blacklisted_token import BlacklistedToken
from app.auth_module.logic import get_password_hash
from app.config import settings
from datetime import datetime, timedelta, timezone
from jose import jwt
from authx import RequestToken # Import RequestToken
import uuid # Import uuid

# Setup test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_temp.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

# Override get_db dependency for testing
app.dependency_overrides[get_db] = override_get_db

client = TestClient(app) # Use the app instance for the TestClient

@pytest.fixture(name="db_session")
def db_session_fixture():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        # Create default organization
        default_org = Organization(name="Test Org")
        db.add(default_org)
        db.commit()
        db.refresh(default_org)

        # Create default role
        admin_role = Role(name="Admin")
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)

        # Create default portal page
        admin_page = PortalPage(endpoint="/admin", name="Admin Dashboard")
        db.add(admin_page)
        db.commit()
        db.refresh(admin_page)

        # Create role detail
        admin_role_detail = RoleDetail(
            role_id=admin_role.id,
            portal_page_id=admin_page.id,
            create=True, view=True, edit=True, remove=True, export=True, print=True, send=True
        )
        db.add(admin_role_detail)
        db.commit()
        db.refresh(admin_role_detail)

        # Create test user
        hashed_password = get_password_hash("testpassword")
        test_user = User(
            username="testuser",
            email="test@example.com",
            name="Test User",
            password=hashed_password,
            status=True,
            approval=True,
            role_id=admin_role.id,
            organization_id=default_org.id
        )
        db.add(test_user)
        db.commit()
        db.refresh(test_user)

        # Create inactive user
        inactive_user = User(
            username="inactiveuser",
            email="inactive@example.com",
            name="Inactive User",
            password=get_password_hash("inactivepassword"),
            status=False,
            approval=True,
            role_id=admin_role.id,
            organization_id=default_org.id
        )
        db.add(inactive_user)
        db.commit()
        db.refresh(inactive_user)

        # Create unapproved user
        unapproved_user = User(
            username="unapproveduser",
            email="unapproved@example.com",
            name="Unapproved User",
            password=get_password_hash("unapprovedpassword"),
            status=True,
            approval=False,
            role_id=admin_role.id,
            organization_id=default_org.id
        )
        db.add(unapproved_user)
        db.commit()
        db.refresh(unapproved_user)

        yield db
    finally:
        db.close()

from app.authx import auth # Import the auth object

def create_test_token(user_id: int, token_type: str, expires_delta: timedelta, data: dict = None):
    to_encode = {"sub": str(user_id), "type": token_type}
    if data:
        to_encode.update(data)
    
    import uuid
    to_encode["jti"] = str(uuid.uuid4()) # Ensure jti is always present

    now = datetime.now(timezone.utc)
    expire = now + expires_delta
    to_encode.update({"exp": expire, "iat": now, "iss": settings.ISSUER, "aud": settings.AUDIENCE})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

# Test /login endpoint
def test_login_success(db_session):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "testpassword"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "tokens" in data
    assert "access" in data["tokens"]
    assert "refresh" in data["tokens"]
    assert data["user"]["username"] == "testuser"
    assert data["user"]["approval"] is True

def test_login_incorrect_password(db_session):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "wrongpassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Incorrect username or password"

def test_login_inactive_user(db_session):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "inactiveuser", "password": "inactivepassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Inactive user"

def test_login_unapproved_user(db_session):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "unapproveduser", "password": "unapprovedpassword"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "User not approved"

# Test /refresh endpoint
@pytest.mark.asyncio
async def test_refresh_token_success(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))
    
    # Manually set the refresh_token_jti for the user in the database
    refresh_payload = auth.verify_token(RequestToken(token=refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = refresh_payload["jti"]
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    response = client.post(
        "/api/v1/auth/refresh",
        data={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    data = response.json()
    assert "tokens" in data
    assert "access" in data["tokens"]
    assert "refresh" in data["tokens"]
    assert data["user"]["username"] == "testuser"

@pytest.mark.asyncio
async def test_refresh_token_missing(db_session):
    response = client.post(
        "/api/v1/auth/refresh",
        data={}
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "refresh_token field required"

@pytest.mark.asyncio
async def test_refresh_token_expired(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    expired_refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=-1)) # Expired token
    
    # Manually set the refresh_token_jti for the user in the database
    # We need to create a token with a past expiry for the JTI to be correctly set in the user model for the test.
    # The `create_test_token` function now uses `auth.create_refresh_token` which includes jti.
    # We will decode it to get the jti, and then re-encode with an expired time.
    
    # Create a token that will be expired
    temp_refresh_token = auth.create_refresh_token(uid=str(user.id), expires_delta=timedelta(minutes=-1))
    temp_payload = jwt.decode(temp_refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], audience=settings.AUDIENCE, issuer=settings.ISSUER)
    
    user.refresh_token_jti = temp_payload["jti"]
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    response = client.post(
        "/api/v1/auth/refresh",
        data={"refresh_token": expired_refresh_token}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token expired or invalid"

@pytest.mark.asyncio
async def test_refresh_token_blacklisted(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))
    
    # Manually set the refresh_token_jti for the user in the database
    refresh_payload = auth.verify_token(RequestToken(token=refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = refresh_payload["jti"]
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Blacklist the token
    blacklisted_token = BlacklistedToken(jti=refresh_payload["jti"], expires_at=datetime.now(timezone.utc) + timedelta(days=1))
    db_session.add(blacklisted_token)
    db_session.commit()

    response = client.post(
        "/api/v1/auth/refresh",
        data={"refresh_token": refresh_token}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token has been blacklisted"

@pytest.mark.asyncio
async def test_refresh_token_jti_mismatch(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    
    # Create a valid refresh token
    valid_refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))
    
    # Create another refresh token, but store the JTI of the first one in the user
    another_refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))
    valid_refresh_payload = auth.verify_token(RequestToken(token=valid_refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = valid_refresh_payload["jti"]
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    response = client.post(
        "/api/v1/auth/refresh",
        data={"refresh_token": another_refresh_token} # Use the token with a different JTI
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid refresh token for user"

# Test /logout endpoint
def test_logout_success(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    access_token = create_test_token(user.id, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))

    # Manually set the refresh_token_jti for the user in the database
    refresh_payload = auth.verify_token(RequestToken(token=refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = refresh_payload["jti"]
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        data={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Successfully logged out"

    # Verify tokens are blacklisted
    access_payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], audience=settings.AUDIENCE, issuer=settings.ISSUER)
    refresh_payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], audience=settings.AUDIENCE, issuer=settings.ISSUER)
    
    assert db_session.query(BlacklistedToken).filter(BlacklistedToken.jti == access_payload["jti"]).first() is not None
    assert db_session.query(BlacklistedToken).filter(BlacklistedToken.jti == refresh_payload["jti"]).first() is not None

def test_logout_invalid_access_token(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    refresh_token = create_test_token(user.id, "refresh", timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES))
    
    # Manually set the refresh_token_jti for the user in the database
    refresh_payload = auth.verify_token(RequestToken(token=refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = refresh_payload["jti"]
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": "Bearer invalid_access_token"},
        data={"refresh_token": refresh_token}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Access token expired or invalid"

def test_logout_invalid_refresh_token(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    access_token = create_test_token(user.id, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    
    # Manually set the refresh_token_jti for the user in the database
    # We don't set it to match the invalid refresh token, simulating a mismatch
    user.refresh_token_jti = "some_other_jti" 
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
        data={"refresh_token": "invalid_refresh_token"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Refresh token expired or invalid"

# Test /forgot-password endpoint
def test_forgot_password_success(db_session):
    response = client.post(
        "/api/v1/auth/forgot-password",
        json={"username": "testuser"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "OTP sent successfully"

def test_forgot_password_user_not_found(db_session):
    response = client.post(
        "/api/v1/auth/forgot-password",
        json={"username": "nonexistentuser"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"

# Test /reset-password endpoint
def test_reset_password_success(db_session):
    # For mock, we assume OTP is always valid
    response = client.post(
        "/api/v1/auth/reset-password",
        json={"username": "testuser", "otp_code": "123456", "new_password": "newtestpassword"}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Password reset successfully"

    # Verify password change by trying to log in with new password
    login_response = client.post(
        "/api/v1/auth/login",
        data={"username": "testuser", "password": "newtestpassword"}
    )
    assert login_response.status_code == 200

def test_reset_password_user_not_found(db_session):
    response = client.post(
        "/api/v1/auth/reset-password",
        json={"username": "nonexistentuser", "otp_code": "123456", "new_password": "newpassword"}
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"

# Test /validate endpoint
def test_validate_token_success(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    access_token = create_test_token(user.id, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    response = client.post(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "testuser"
    assert data["approval"] is True

def test_validate_token_invalid_token(db_session):
    response = client.post(
        "/api/v1/auth/validate",
        headers={"Authorization": "Bearer invalid_token"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Could not validate credentials"

def test_validate_token_expired_token(db_session):
    user = db_session.query(User).filter(User.username == "testuser").first()
    expired_access_token = create_test_token(user.id, "access", timedelta(minutes=-1))
    response = client.post(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {expired_access_token}"}
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Could not validate credentials"

def test_validate_token_user_not_found(db_session):
    # Create a token for a non-existent user ID
    non_existent_user_id = 9999
    access_token = create_test_token(non_existent_user_id, "access", timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    response = client.post(
        "/api/v1/auth/validate",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
