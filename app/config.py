import os

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60
    ISSUER: str = "your-app-issuer"
    AUDIENCE: str = "your-app-audience"
    OTP_EXPIRE_MINUTES: int = 5

settings = Settings()
