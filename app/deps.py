from typing import Generator, Tuple
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.authx import auth
from authx.exceptions import JWTDecodeError, AccessTokenRequiredError
from authx import RequestToken
from app.auth_module import logic as auth_logic
from app.auth_module import schemas as auth_schemas
from app.models.user import User # Import the User model

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> Tuple[auth_schemas.UserInfoWithPermissions, auth_schemas.AccessTokenPayload]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        request_token = RequestToken(token=token, location="headers")
        raw_payload = auth.verify_token(request_token)
        payload = auth_schemas.AccessTokenPayload(**raw_payload.model_dump())
    except (JWTDecodeError, AccessTokenRequiredError):
        raise credentials_exception
    
    user = auth_logic.get_user_with_permissions(db, user_id=payload.sub)
    if user is None:
        raise credentials_exception
    
    permissions = {}
    if user.role:
        for detail in user.role.details:
            subject = detail.portal_page.endpoint
            actions = [
                action
                for action, has_perm in [
                    ("create", detail.create),
                    ("view", detail.view),
                    ("edit", detail.edit),
                    ("delete", detail.remove),
                    ("export", detail.export),
                    ("print", detail.print),
                    ("send", detail.send),
                ]
                if has_perm
            ]
            if subject not in permissions:
                permissions[subject] = {"subject": subject, "actions": []}
            permissions[subject]["actions"].extend(actions)
    
    user_info = auth_schemas.UserInfoWithPermissions(
        id=user.id,
        name=user.name,
        email=user.email,
        username=user.username,
        avatar=user.avatar, # Simplified for mock
        role=list(permissions.values()),
        role_name=user.role.name if user.role else None,
        approval=user.approval,
        organization_id=user.organization.id if user.organization else None,
        organization_name=user.organization.name if user.organization else None,
    )
    return user_info, payload
