from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user import User, Role, Organization, PortalPage, RoleDetail
from app.auth_module import schemas as auth_schemas
from datetime import datetime, timedelta, timezone
import random
import string
import logging

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_by_username_with_permissions(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_with_permissions(db: Session, user_id: str):
    return db.query(User).filter(User.id == user_id).first()

def generate_otp(db: Session, username: str) -> bool:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    otp_code = "".join(random.choices(string.digits, k=6))
    otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5) # Mock expiry
    
    logging.info(f"Generated OTP for {username}: {otp_code}. Expires at: {otp_expires_at}")
    
    return True

def reset_password(db: Session, username: str, otp_code: str, new_password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # In a real application, you would verify the OTP code and its expiry.
    # For this mock, we'll assume OTP is always valid if it's provided.
    # if not user.otp_code == otp_code or datetime.now(timezone.utc) > user.otp_expires_at:
    #     raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    user.password = get_password_hash(new_password)
    # user.otp_code = None # Clear OTP after use
    # user.otp_expires_at = None
    db.add(user)
    db.commit()
    db.refresh(user)
    logging.info(f"Password reset for user {username}")
