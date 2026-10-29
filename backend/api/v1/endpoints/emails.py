import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pymongo.errors import PyMongoError

from core.config import settings
from core.database import emails_collection
from core.security import get_optional_current_user
from core.storage import delete_email_file, upload_email_file
from schemas.email import EmailAnalysisResponse, EmailListResponse
from services.authentication.verifier import analyze_authentication
from services.email.header_analyzer import analyze_header_consistency
from services.email.parser import parse_eml
from services.email.relay_analyzer import analyze_relays
from services.email.risk_scorer import score_risk
from services.email.url_analyzer import analyze_email_urls
from services.email.url_extractor import extract_email_urls
from services.evidence.normalizer import normalize_forensic_evidence
from services.investigation.graph_service import (
    correlate_email_campaigns,
    index_email_graph_entities,
)
from services.scoring.formula_scorer import calculate_formula_score
from services.scoring.subjective_logic import evaluate_subjective_logic
from utils.hashing import calculate_sha256

router = APIRouter()

MAX_UPLOAD_SIZE = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024


@router.post("/upload", status_code=201, response_model=EmailAnalysisResponse)
async def upload_email(
    file: UploadFile = File(...),
    current_user: dict[str, Any] | None = Depends(get_optional_current_user),
):
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

        received_headers = (parsed_email.get("headers") or {}).get("received") or []
        relay_analysis = analyze_relays(received_headers)

        evidence_objs = normalize_forensic_evidence(
            parsed_email,
            authentication,
            url_analysis,
            header_analysis,
            relay_analysis,
            investigation_id=email_id,
        )
        scoring_breakdown = calculate_formula_score(evidence_objs)
        opinion_model = evaluate_subjective_logic(evidence_objs)

        evidence_data = [ev.model_dump() for ev in evidence_objs]
        scoring_data = scoring_breakdown.model_dump()
        opinion_data = opinion_model.model_dump()

        try:
            await asyncio.to_thread(upload_email_file, file_data, storage_path)
        except Exception as exc:
            logging.exception("Supabase storage upload failed")
            raise HTTPException(
                status_code=503,
                detail="Unable to store the original email in object storage.",
            ) from exc

        uploaded_at = datetime.now(timezone.utc)
        user_id = current_user.get("id") if isinstance(current_user, dict) else None

        try:
            await index_email_graph_entities(email_id, parsed_email, urls, relay_analysis)
            campaign_correlation = await correlate_email_campaigns(
                email_id, parsed_email, urls, relay_analysis
            )
        except Exception:
            campaign_correlation = {
                "campaign_id": None,
                "is_correlated": False,
                "confidence": 0.0,
                "related_email_ids": [],
                "reasons": [],
            }

        document = {
            "_id": email_id,
            "filename": safe_filename,
            "sha256": file_hash,
            "storage_path": storage_path,
            "uploaded_at": uploaded_at,
            "user_id": user_id,
            "email": parsed_email,
            "authentication": authentication,
            "urls": urls,
            "url_analysis": url_analysis,
            "header_analysis": header_analysis,
            "risk_assessment": risk_assessment,
            "relay_analysis": relay_analysis,
            "evidence": evidence_data,
            "scoring_details": scoring_data,
            "subjective_logic": opinion_data,
            "campaign_correlation": campaign_correlation,
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
            "user_id": user_id,
            "email": parsed_email,
            "authentication": authentication,
            "urls": urls,
            "url_analysis": url_analysis,
            "header_analysis": header_analysis,
            "risk_assessment": risk_assessment,
            "relay_analysis": relay_analysis,
            "evidence": evidence_data,
            "scoring_details": scoring_data,
            "subjective_logic": opinion_data,
            "campaign_correlation": campaign_correlation,
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
