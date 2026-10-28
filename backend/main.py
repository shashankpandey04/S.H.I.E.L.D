import os
import sys
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.v1.router import api_router
from core.config import settings
from core.database import close_mongodb_connection, connect_to_mongodb


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await connect_to_mongodb()
    except Exception:
        pass
    yield
    try:
        await close_mongodb_connection()
    except Exception:
        pass


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI Email Threat Detection & Forensic Intelligence",
    debug=settings.DEBUG,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", tags=["General"])
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "message": "Email threat analysis and forensic intelligence API",
        "docs": "/docs",
    }
