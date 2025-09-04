from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from jose import jwt, JWTError
from authx.exceptions import JWTDecodeError, AccessTokenRequiredError
from authx import RequestToken
from app.config import settings

class AuthX:
    def __init__(self, secret_key: str, algorithm: str, access_token_expire_minutes: int, refresh_token_expire_minutes: int, issuer: str, audience: str):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_minutes = refresh_token_expire_minutes
        self.issuer = issuer
        self.audience = audience

    def create_token(self, uid: str, token_type: str, expires_delta: Optional[timedelta] = None, data: Optional[Dict[str, Any]] = None) -> str:
        import uuid
        to_encode = {"sub": uid, "type": token_type, "jti": str(uuid.uuid4())} # Add jti claim
        if data:
            to_encode.update(data)
        
        now = datetime.now(timezone.utc)
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(minutes=self.access_token_expire_minutes if token_type == "access" else self.refresh_token_expire_minutes)
        
        to_encode.update({"exp": expire, "iat": now, "iss": self.issuer, "aud": self.audience})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_access_token(self, uid: str, data: Optional[Dict[str, Any]] = None) -> str:
        return self.create_token(uid, "access", timedelta(minutes=self.access_token_expire_minutes), data)

    def create_refresh_token(self, uid: str, data: Optional[Dict[str, Any]] = None) -> str:
        return self.create_token(uid, "refresh", timedelta(minutes=self.refresh_token_expire_minutes), data)

    def verify_token(self, request_token: RequestToken, verify_type: bool = True) -> Dict[str, Any]:
        token = request_token.token
        if not token:
            raise AccessTokenRequiredError("Token is missing")
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], audience=self.audience, issuer=self.issuer)
            if verify_type and payload.get("type") != "access":
                raise AccessTokenRequiredError("Invalid token type / Access token required")
            return payload
        except jwt.ExpiredSignatureError:
            raise JWTDecodeError("Token has expired")
        except JWTError as e:
            raise JWTDecodeError(f"Token verification failed: {e}")

auth = AuthX(
    secret_key=settings.SECRET_KEY,
    algorithm=settings.ALGORITHM,
    access_token_expire_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    refresh_token_expire_minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES,
    issuer=settings.ISSUER,
    audience=settings.AUDIENCE
)
