import asyncio
from pymongo import ASCENDING, DESCENDING, AsyncMongoClient
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase

from core.config import settings

client = AsyncMongoClient(
    settings.MONGODB_URI,
    serverSelectionTimeoutMS=2000,
    connectTimeoutMS=2000,
)

database: AsyncDatabase = client[settings.MONGODB_DATABASE]
emails_collection: AsyncCollection = database["emails"]


async def connect_to_mongodb() -> None:
    try:
        await asyncio.wait_for(client.admin.command("ping"), timeout=2.0)
        await emails_collection.create_index(
            [("uploaded_at", DESCENDING)],
            name="uploaded_at_desc",
        )
        await emails_collection.create_index(
            [("sha256", ASCENDING)],
            name="sha256_asc",
        )
    except Exception:
        pass


async def close_mongodb_connection() -> None:
    try:
        await client.close()
    except Exception:
        pass
