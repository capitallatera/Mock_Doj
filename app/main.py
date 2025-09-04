import logging
from datetime import timedelta, datetime, timezone
from fastapi import FastAPI, APIRouter, Depends, HTTPException, Request, Form
from app.ratelimit import limiter, RateLimitMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.sql import exists
from authx.exceptions import JWTDecodeError, AccessTokenRequiredError
from app.deps import get_db, get_current_user
from app.authx import auth
from authx import RequestToken
from app.config import settings
from app.models.blacklisted_token import BlacklistedToken
from app.auth_module import logic as auth_logic 
from app.auth_module import schemas as auth_schemas 
from app.schemas.dropdown import Error401, Error403, Error422, Error500, Default
import os 
from app.middlewares.file_proxy import get_file_url


router = APIRouter(prefix="/api/v1/auth")

app = FastAPI()
app.include_router(router)
# app.add_middleware(RateLimitMiddleware, limiter=limiter) # Temporarily disable for testing


@router.post("/login", status_code=200, tags=["auth"],
            description="Authenticate user and retrieve access and refresh tokens.",
            summary="User Login", response_model=auth_schemas.Token,
            responses={401: {"model": Error401}, 403: {"model": Error403}, 422: {"model": Error422}, 500: {"model": Error500}, "default": {"model": Default}},
            operation_id="login_access_token")
def login_access_token(
    request: Request,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Authenticates a user with username and password, returning access and refresh tokens upon successful login.
    Includes checks for user status and approval.
    """
    user = auth_logic.get_by_username_with_permissions(db, username=form_data.username)
    if not user or not auth_logic.verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    elif not user.status:
        raise HTTPException(status_code=400, detail="Inactive user")
    elif not user.approval: # New approval check
        raise HTTPException(status_code=400, detail="User not approved")

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
        avatar=get_file_url(request, os.path.basename(user.avatar)) if user.avatar else None,
        role=list(permissions.values()),
        role_name=user.role.name if user.role else None,
        approval=user.approval,
        organization_id=user.organization.id if user.organization else None,
        organization_name=user.organization.name if user.organization else None,
    )

    access_token = auth.create_access_token(uid=str(user.id), data={"organization_id": user.organization_id, "organization_name": user.organization.name if user.organization else None, "role_name": user.role.name if user.role else None})
    refresh_token = auth.create_refresh_token(uid=str(user.id), data={"organization_id": user.organization_id, "organization_name": user.organization.name if user.organization else None, "role_name": user.role.name if user.role else None})

   
    refresh_token_payload = auth.verify_token(RequestToken(token=refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = refresh_token_payload.jti
    db.add(user)
    db.commit()
    db.refresh(user)
    logging.info(f"Login: Saved refresh token JTI for user {user.username}: {user.refresh_token_jti}")

    now = datetime.now(timezone.utc)
    return {
        "tokens": {"access": access_token, "refresh": refresh_token},
        "iss": settings.ISSUER,
        "aud": settings.AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "user": user_info,
    }

def cleanup_expired_tokens(db: Session):
    db.query(BlacklistedToken).filter(
        BlacklistedToken.expires_at < datetime.now(timezone.utc)
    ).delete(synchronize_session=False)
    db.commit()

@router.post("/refresh", status_code=200, tags=["auth"],
            description="Refresh the access token",
            summary="Refresh token", response_model=auth_schemas.TokenWithRefresh,
            responses={401: {"model": Error401}, 403: {"model": Error403}},
            operation_id="refresh_token")
async def refresh_token(request: Request, db: Session = Depends(get_db)):
    """
    Refresh the access token using a valid refresh token.
    """
    form_data = await request.form()
    refresh_token_str = form_data.get("refresh_token")
    if not refresh_token_str:
        raise HTTPException(status_code=422, detail="refresh_token field required")
    try:
        request_token = RequestToken(token=refresh_token_str, location="json")
        payload = auth.verify_token(request_token, verify_type=False) # Revert to verify_type=False
        if payload.type != "refresh":
            raise HTTPException(status_code=403, detail="'refresh' token required, 'access' token received")
        
        # Manual check for expired refresh token
        if payload.exp is None: # Check if exp claim is missing
            raise HTTPException(status_code=401, detail="Refresh token expired or invalid")
        if payload.exp < datetime.now(timezone.utc): # Direct comparison of datetime objects
            raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

        # Check if the token is blacklisted
        jti = payload.jti
        if db.query(BlacklistedToken).filter(BlacklistedToken.jti == jti).first():
            raise HTTPException(status_code=401, detail="Refresh token has been blacklisted")

    except JWTDecodeError as e:
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")
    
    # If valid, issue new tokens
    user_id = payload.sub
    user = auth_logic.get_user_with_permissions(db, user_id=user_id) # Fetch user with permissions
    if not user:
        logging.warning(f"Refresh: User not found for ID: {user_id}")
        raise HTTPException(status_code=404, detail="User not found")

    # Extract JTI from the incoming refresh token
    incoming_refresh_token_payload = auth.verify_token(RequestToken(token=refresh_token_str, location="json"), verify_type=False)
    incoming_refresh_jti = incoming_refresh_token_payload.jti

    logging.info(f"Refresh: Incoming refresh token JTI: {incoming_refresh_jti}")
    logging.info(f"Refresh: Stored refresh token JTI for user {user.username}: {user.refresh_token_jti}")

    # Validate if the refresh token JTI from the request matches the one stored in the database
    if user.refresh_token_jti != incoming_refresh_jti:
        logging.warning(f"Refresh: JTI mismatch for user {user.username}. Incoming JTI: {incoming_refresh_jti}, Stored JTI: {user.refresh_token_jti}")
        raise HTTPException(status_code=401, detail="Invalid refresh token for user")

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
        avatar=get_file_url(request, os.path.basename(user.avatar)) if user.avatar else None,
        role=list(permissions.values()),
        role_name=user.role.name if user.role else None,
        approval=user.approval,
        organization_id=user.organization.id if user.organization else None,
        organization_name=user.organization.name if user.organization else None,
    )

    access_token = auth.create_access_token(uid=str(user.id), data={"organization_id": user.organization_id, "organization_name": user.organization.name if user.organization else None, "role_name": user.role.name if user.role else None})
    new_refresh_token = auth.create_refresh_token(uid=str(user.id), data={"organization_id": user.organization_id, "organization_name": user.organization.name if user.organization else None, "role_name": user.role.name if user.role else None})

    # Update the user's refresh token JTI in the database
    new_refresh_token_payload = auth.verify_token(RequestToken(token=new_refresh_token, location="json"), verify_type=False)
    user.refresh_token_jti = new_refresh_token_payload.jti
    db.add(user)
    db.commit()
    db.refresh(user)
    logging.info(f"Refresh: New refresh token JTI saved for user {user.username}: {user.refresh_token_jti}")

    now = datetime.now(timezone.utc)
    return {
        "tokens": {"access": access_token, "refresh": new_refresh_token},
        "iss": settings.ISSUER,
        "aud": settings.AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "user": user_info,
    }
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

@router.post("/logout", status_code=200, tags=["auth"],
            description="Invalidates the current access and refresh tokens, effectively logging out the user.",
            summary="User Logout", response_model=auth_schemas.LogoutResponse,
            responses={401: {"model": Error401}, 403: {"model": Error403}, 422: {"model": Error422}, 500: {"model": Error500}, "default": {"model": Default}},
            operation_id="logout_user")
def logout(
    token: str = Depends(oauth2_scheme),
    refresh_token: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Logs out the current user by blacklisting their access and refresh tokens.
    """
    cleanup_expired_tokens(db)
    user_id = "unknown"
    try:
        request_token = RequestToken(token=token, location="headers")
        raw_access_payload = auth.verify_token(request_token)
        access_payload = auth_schemas.AccessTokenPayload(**raw_access_payload.model_dump())
        user_id = access_payload.sub
        access_jti = access_payload.jti
        access_token_expires = access_payload.exp
        if (
            access_jti
            and not db.query(exists().where(BlacklistedToken.jti == access_jti)).scalar()
        ):
            db.add(BlacklistedToken(jti=access_jti, expires_at=access_token_expires)) # Pass datetime object directly
            logging.info(f"Access Token of {user_id} added to blacklist.")
    except JWTDecodeError:
        raise HTTPException(status_code=403, detail="Access token expired or invalid")
    except AccessTokenRequiredError: # Catch specific error for wrong token type
        raise HTTPException(status_code=403, detail="Invalid token type / Invalid token")
    try:
        request_token = RequestToken(token=refresh_token, location="headers")
        raw_refresh_payload = auth.verify_token(request_token, verify_type=False)
        refresh_payload = auth_schemas.RefreshTokenPayload(**raw_refresh_payload.model_dump())
        user_id = refresh_payload.sub
        refresh_jti = refresh_payload.jti
        refresh_token_expires = refresh_payload.exp
        if (
            refresh_jti
            and not db.query(exists().where(BlacklistedToken.jti == refresh_jti)).scalar()
        ):
            db.add(
                BlacklistedToken(jti=refresh_jti, expires_at=refresh_token_expires) # Pass datetime object directly
            )
            logging.info(f"Refresh Token of {user_id} added to blacklist.")
    except JWTDecodeError:
        raise HTTPException(status_code=401, detail="Refresh token expired or invalid")
    db.commit()
    logging.info("--- Finished Logout Process ---")
    return {"message": "Successfully logged out"}

@router.post("/forgot-password", status_code=200, tags=["auth"],
            description="Requests a One-Time Password (OTP) to be sent to the user's registered email for password reset.",
            summary="Request Password Reset OTP",
            responses={404: {"model": Error401}, 406: {"model": Error403}, 422: {"model": Error422}, 500: {"model": Error500}, "default": {"model": Default}},
            operation_id="forgot_password_request_otp")
async def forgot_password(
    forgot_password_request: auth_schemas.ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Sends an OTP to the user's registered email to initiate the password reset process.
    """
    try:
        success = auth_logic.generate_otp(db, str(forgot_password_request.username))
        if not success:
            raise HTTPException(status_code=404, detail="User not found")
        return {"message": "OTP sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=404,detail="User not Found")

@router.post("/reset-password", status_code=200, tags=["auth"],
            description="Resets the user's password using a verified OTP and a new password.",
            summary="Reset User Password",
            responses={400: {"model": Error401}, 404: {"model": Error403}, 422: {"model": Error422}, 500: {"model": Error500}, "default": {"model": Default}},
            operation_id="reset_user_password")
async def reset_password(
    reset_password_request: auth_schemas.ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Resets a user's password after successful OTP verification.
    """
    try:
        auth_logic.reset_password(db, reset_password_request.username, reset_password_request.otp_code, reset_password_request.new_password)
        return {"message": "Password reset successfully"}
    except HTTPException as e: # Catch and re-raise HTTPException directly
        raise e
    except Exception as e:
        raise HTTPException(status_code=406, detail=f"Error resetting password: {e}")

@router.post(
    "/validate",
    summary="Validate token",
    tags=["auth"],
    description="Validate access token.",
    response_model=auth_schemas.UserInfo,
    responses={
        200: {"description": "Successful Response"},
        401: {
            "description": "Token has been blacklisted",
            "model": auth_schemas.HTTPError,
        },
        403: {
            "description": "Invalid token type / Invalid token",
            "model": auth_schemas.HTTPError,
        },
        404: {
            "description": "User not found",
            "model": auth_schemas.HTTPError,
        },
    },
)
def validate_token(
    user_payload_tuple: tuple = Depends(get_current_user),
):  
    """
    Validate access token.
    """
    try:
        current_user, _ = user_payload_tuple
        return current_user
    except JWTDecodeError:
        raise HTTPException(status_code=403, detail="Access token expired or invalid")
