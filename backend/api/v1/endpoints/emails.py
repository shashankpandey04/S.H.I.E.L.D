import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pymongo.errors import PyMongoError

from core.config import settings
from core.database import emails_collection
from core.storage import delete_email_file, upload_email_file
from schemas.email import EmailAnalysisResponse, EmailListResponse
from services.authentication.verifier import analyze_authentication
from services.email.header_analyzer import analyze_header_consistency
from services.email.parser import parse_eml
from services.email.risk_scorer import score_risk
from services.email.url_analyzer import analyze_email_urls
from services.email.url_extractor import extract_email_urls
from utils.hashing import calculate_sha256

router = APIRouter()

MAX_UPLOAD_SIZE = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@router.post("/upload", status_code=201, response_model=EmailAnalysisResponse)
async def upload_email(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is missing.",
        )

    safe_filename = Path(file.filename).name
    if Path(safe_filename).suffix.lower() != ".eml":
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    file_data = await file.read(MAX_UPLOAD_SIZE + 1)
    await file.close()

    if not file_data:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file is empty.",
        )

    if len(file_data) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB limit.",
        )

    file_hash = calculate_sha256(file_data)
    email_id = str(uuid4())
    storage_path = f"{datetime.now(timezone.utc):%Y/%m/%d}/{email_id}.eml"

    try:
        parsed_email = parse_eml(file_data, safe_filename)
        authentication = await asyncio.to_thread(
            analyze_authentication,
            parsed_email,
            file_data,
        )
        urls = extract_email_urls(parsed_email)
        url_analysis = analyze_email_urls(urls)
        header_analysis = analyze_header_consistency(parsed_email)
        risk_assessment = score_risk(
            parsed_email,
            authentication,
            url_analysis,
            header_analysis,
        )

        try:
            await asyncio.to_thread(upload_email_file, file_data, storage_path)
        except Exception as exc:
            logging.exception("Supabase storage upload failed")
            raise HTTPException(
                status_code=503,
                detail="Unable to store the original email in object storage.",
            ) from exc

        uploaded_at = datetime.now(timezone.utc)

        document = {
            "_id": email_id,
            "filename": safe_filename,
            "sha256": file_hash,
            "storage_path": storage_path,
            "uploaded_at": uploaded_at,
            "email": parsed_email,
            "authentication": authentication,
            "urls": urls,
            "url_analysis": url_analysis,
            "header_analysis": header_analysis,
            "risk_assessment": risk_assessment,
            "status": "analyzed",
        }

        try:
            await emails_collection.insert_one(document)
        except PyMongoError as exc:
            try:
                await asyncio.to_thread(delete_email_file, storage_path)
            except Exception:
                logging.exception("Failed to clean up uploaded file after DB failure")
            raise HTTPException(
                status_code=503,
                detail="Unable to save the email record to the database.",
            ) from exc

        return {
            "id": email_id,
            "filename": document["filename"],
            "sha256": file_hash,
            "storage_path": storage_path,
            "uploaded_at": uploaded_at,
            "status": document["status"],
            "email": parsed_email,
            "authentication": authentication,
            "urls": urls,
            "url_analysis": url_analysis,
            "header_analysis": header_analysis,
            "risk_assessment": risk_assessment,
        }

    except HTTPException:
        raise

    except Exception as exc:
        logging.exception("Email upload failed")
        raise HTTPException(
            status_code=500,
            detail="Email processing failed.",
        ) from exc


@router.get("/", response_model=EmailListResponse)
async def list_emails(
    limit: int = Query(default=20, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
):
    try:
        cursor = (
            emails_collection.find(
                {},
                {
                    "email.body": 0,
                    "email.authentication_headers": 0,
                },
            )
            .sort("uploaded_at", -1)
            .skip(skip)
            .limit(limit)
        )

        emails = []
        async for document in cursor:
            document["id"] = document.pop("_id")
            emails.append(document)

        total = await emails_collection.count_documents({})

        return {
            "total": total,
            "limit": limit,
            "skip": skip,
            "emails": emails,
        }

    except PyMongoError as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve email analysis history.",
        ) from exc


@router.get("/{email_id}", response_model=EmailAnalysisResponse)
async def get_email_analysis(email_id: str):
    try:
        document = await emails_collection.find_one({"_id": email_id})

        if document is None:
            raise HTTPException(
                status_code=404,
                detail="Email analysis not found.",
            )

        document["id"] = document.pop("_id")
        return document

    except HTTPException:
        raise

    except PyMongoError as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve email analysis.",
        ) from exc
