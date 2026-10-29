from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException, status

from core.config import settings
from core.database import refresh_tokens_collection, users_collection
from core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from schemas.auth import UserLoginRequest, UserRegisterRequest


async def register_user(request: UserRegisterRequest) -> dict:
    normalized_email = request.email.strip().lower()

    existing = await users_collection.find_one({"email": normalized_email})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email address already exists.",
        )

    user_id = str(uuid4())
    now = datetime.now(timezone.utc)

    user_doc = {
        "_id": user_id,
        "email": normalized_email,
        "password_hash": hash_password(request.password),
        "full_name": request.full_name.strip() if request.full_name else None,
        "role": "user",
        "is_active": True,
        "created_at": now,
        "last_login_at": None,
    }

    await users_collection.insert_one(user_doc)
    return {
        "id": user_id,
        "email": user_doc["email"],
        "full_name": user_doc["full_name"],
        "role": user_doc["role"],
        "is_active": user_doc["is_active"],
        "created_at": user_doc["created_at"],
        "last_login_at": None,
    }


async def authenticate_user(request: UserLoginRequest) -> dict:
    normalized_email = request.email.strip().lower()

    user = await users_collection.find_one({"email": normalized_email})
    if not user or not verify_password(request.password, user.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    now = datetime.now(timezone.utc)
    await users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login_at": now}},
    )

    access_token, _ = create_access_token(user["_id"], user["email"], user.get("role", "user"))
    raw_refresh_token = generate_refresh_token()
    token_hash = hash_refresh_token(raw_refresh_token)

    family_id = str(uuid4())
    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    refresh_doc = {
        "_id": str(uuid4()),
        "token_hash": token_hash,
        "user_id": user["_id"],
        "family_id": family_id,
        "created_at": now,
        "expires_at": expires_at,
        "revoked_at": None,
    }
    await refresh_tokens_collection.insert_one(refresh_doc)

    user_info = {
        "id": user["_id"],
        "email": user["email"],
        "full_name": user.get("full_name"),
        "role": user.get("role", "user"),
        "is_active": user.get("is_active", True),
        "created_at": user.get("created_at", now),
        "last_login_at": now,
    }

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": user_info,
    }


async def refresh_tokens(raw_refresh_token: str) -> dict:
    token_hash = hash_refresh_token(raw_refresh_token)
    stored_token = await refresh_tokens_collection.find_one({"token_hash": token_hash})

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    now = datetime.now(timezone.utc)

    # Invalidate family on reuse
    if stored_token.get("revoked_at") is not None:
        await refresh_tokens_collection.update_many(
            {"family_id": stored_token["family_id"]},
            {"$set": {"revoked_at": now}},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected; session revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    expires_at = stored_token.get("expires_at")
    if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if not expires_at or expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await users_collection.find_one({"_id": stored_token["user_id"]})
    if not user or not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is invalid or deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await refresh_tokens_collection.update_one(
        {"_id": stored_token["_id"]},
        {"$set": {"revoked_at": now}},
    )

    new_access_token, _ = create_access_token(user["_id"], user["email"], user.get("role", "user"))
    new_raw_refresh = generate_refresh_token()
    new_token_hash = hash_refresh_token(new_raw_refresh)
    new_expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    new_refresh_doc = {
        "_id": str(uuid4()),
        "token_hash": new_token_hash,
        "user_id": user["_id"],
        "family_id": stored_token["family_id"],
        "created_at": now,
        "expires_at": new_expires_at,
        "revoked_at": None,
    }
    await refresh_tokens_collection.insert_one(new_refresh_doc)

    user_info = {
        "id": user["_id"],
        "email": user["email"],
        "full_name": user.get("full_name"),
        "role": user.get("role", "user"),
        "is_active": user.get("is_active", True),
        "created_at": user.get("created_at", now),
        "last_login_at": user.get("last_login_at"),
    }

    return {
        "access_token": new_access_token,
        "refresh_token": new_raw_refresh,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": user_info,
    }


async def revoke_refresh_token(raw_refresh_token: str) -> None:
    token_hash = hash_refresh_token(raw_refresh_token)
    await refresh_tokens_collection.update_one(
        {"token_hash": token_hash},
        {"$set": {"revoked_at": datetime.now(timezone.utc)}},
    )
