from sqlalchemy import Column, Integer, String, DateTime
from app.database import Base

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True)
    expires_at = Column(DateTime)
