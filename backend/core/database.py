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
users_collection: AsyncCollection = database["users"]
refresh_tokens_collection: AsyncCollection = database["refresh_tokens"]
investigations_collection: AsyncCollection = database["investigations"]
evidence_collection: AsyncCollection = database["evidence"]
graph_nodes_collection: AsyncCollection = database["graph_nodes"]
graph_edges_collection: AsyncCollection = database["graph_edges"]


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
        await emails_collection.create_index(
            [("user_id", ASCENDING)],
            name="email_user_id_asc",
        )
        await users_collection.create_index(
            [("email", ASCENDING)],
            unique=True,
            name="email_unique",
        )
        await refresh_tokens_collection.create_index(
            [("token_hash", ASCENDING)],
            unique=True,
            name="token_hash_unique",
        )
        await refresh_tokens_collection.create_index(
            [("user_id", ASCENDING)],
            name="rt_user_id_asc",
        )
        await refresh_tokens_collection.create_index(
            [("family_id", ASCENDING)],
            name="rt_family_id_asc",
        )
        await investigations_collection.create_index(
            [("email_id", ASCENDING)],
            name="inv_email_id_asc",
        )
        await investigations_collection.create_index(
            [("user_id", ASCENDING)],
            name="inv_user_id_asc",
        )
        await investigations_collection.create_index(
            [("status", ASCENDING)],
            name="inv_status_asc",
        )
        await evidence_collection.create_index(
            [("investigation_id", ASCENDING)],
            name="ev_inv_id_asc",
        )
        await graph_nodes_collection.create_index(
            [("entity_type", ASCENDING), ("value", ASCENDING)],
            unique=True,
            name="node_type_val_unique",
        )
        await graph_edges_collection.create_index(
            [("source", ASCENDING), ("target", ASCENDING), ("relation", ASCENDING)],
            unique=True,
            name="edge_unique",
        )
    except Exception:
        pass


async def close_mongodb_connection() -> None:
    try:
        await client.close()
    except Exception:
        pass
