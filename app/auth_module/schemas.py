from typing import List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

class HTTPError(BaseModel):
    detail: str

class UserInfo(BaseModel):
    id: int
    name: str
    email: EmailStr
    username: str
    avatar: Optional[str] = None
    approval: bool

class Permission(BaseModel):
    subject: str
    actions: List[str]

class UserInfoWithPermissions(UserInfo):
    role: List[Permission]
    role_name: Optional[str] = None
    organization_id: Optional[int] = None
    organization_name: Optional[str] = None

class Token(BaseModel):
    tokens: dict
    iss: str
    aud: str
    iat: datetime
    exp: datetime
    user: UserInfoWithPermissions

class TokenWithRefresh(BaseModel):
    tokens: dict
    iss: str
    aud: str
    iat: datetime
    exp: datetime
    user: UserInfoWithPermissions

class LogoutResponse(BaseModel):
    message: str

class ForgotPasswordRequest(BaseModel):
    username: str

class ResetPasswordRequest(BaseModel):
    username: str
    otp_code: str
    new_password: str

class AccessTokenPayload(BaseModel):
    sub: str
    jti: str
    exp: datetime
    type: str = "access"

class RefreshTokenPayload(BaseModel):
    sub: str
    jti: str
    exp: datetime
    type: str = "refresh"
