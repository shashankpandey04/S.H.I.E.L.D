from fastapi import APIRouter

from api.v1.endpoints import auth, emails, health, investigations

api_router = APIRouter()

api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)

api_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health"],
)

api_router.include_router(
    emails.router,
    prefix="/emails",
    tags=["Emails"],
)

api_router.include_router(
    investigations.router,
    prefix="/investigations",
    tags=["Investigations"],
)
