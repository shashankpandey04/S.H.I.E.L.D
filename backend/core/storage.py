from pathlib import PurePosixPath

from supabase import Client, create_client

from core.config import settings

supabase: Client = create_client(
    settings.SUPABASE_URL,
    settings.SUPABASE_SERVICE_ROLE_KEY,
)


def upload_email_file(
    file_data: bytes,
    storage_path: str,
) -> str:
    safe_path = str(PurePosixPath(storage_path))

    supabase.storage.from_(
        settings.SUPABASE_EMAILS_BUCKET
    ).upload(
        path=safe_path,
        file=file_data,
        file_options={
            "content-type": "message/rfc822",
            "upsert": "false",
        },
    )

    return safe_path


def download_email_file(storage_path: str) -> bytes:
    file_data = supabase.storage.from_(
        settings.SUPABASE_EMAILS_BUCKET
    ).download(storage_path)

    return bytes(file_data)


def delete_email_file(storage_path: str) -> None:
    safe_path = str(PurePosixPath(storage_path))

    supabase.storage.from_(
        settings.SUPABASE_EMAILS_BUCKET
    ).remove([safe_path])
