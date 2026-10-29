from typing import Any

from fastapi import APIRouter, Depends, status

from core.security import get_current_user
from schemas.auth import (
    MessageResponse,
    RefreshTokenRequest,
    RevokeTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)
from services.auth.auth_service import (
    authenticate_user,
    refresh_tokens,
    register_user,
    revoke_refresh_token,
)

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(request: UserRegisterRequest):
    return await register_user(request)


@router.post("/login", response_model=TokenResponse)
async def login(request: UserLoginRequest):
    return await authenticate_user(request)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: RefreshTokenRequest):
    return await refresh_tokens(request.refresh_token)


@router.post("/logout", response_model=MessageResponse)
async def logout(request: RevokeTokenRequest):
    await revoke_refresh_token(request.refresh_token)
    return {"message": "Session successfully terminated."}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict[str, Any] = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user.get("full_name"),
        "role": current_user.get("role", "user"),
        "is_active": current_user.get("is_active", True),
        "created_at": current_user.get("created_at"),
        "last_login_at": current_user.get("last_login_at"),
    }
