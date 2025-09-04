from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from collections import defaultdict
import time

class RateLimiter:
    def __init__(self, rate: int, period: int):
        self.rate = rate  # Max requests
        self.period = period  # Time window in seconds
        self.clients = defaultdict(list)

    async def __call__(self, request: Request):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Remove expired timestamps
        self.clients[client_ip] = [t for t in self.clients[client_ip] if t > now - self.period]

        if len(self.clients[client_ip]) >= self.rate:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later."
            )
        
        self.clients[client_ip].append(now)

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter):
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(self, request: Request, call_next):
        try:
            await self.limiter(request)
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
        return await call_next(request)

# Example usage: 10 requests per 60 seconds
limiter = RateLimiter(rate=10, period=60)
