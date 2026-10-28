from fastapi import APIRouter

from core.config import settings

router = APIRouter()

@router.get("/")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }