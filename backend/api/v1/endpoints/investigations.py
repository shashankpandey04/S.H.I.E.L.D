from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status

from core.database import emails_collection, investigations_collection
from core.security import get_current_user
from schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationListResponse,
    InvestigationNote,
    InvestigationNoteRequest,
    InvestigationResponse,
    InvestigationUpdateRequest,
)
from services.investigation.report_service import generate_forensic_report

router = APIRouter()


@router.post(
    "/",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_investigation(
    request: InvestigationCreateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    email_doc = await emails_collection.find_one({"_id": request.email_id})
    if not email_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referenced email analysis does not exist.",
        )

    email_subject = ((email_doc.get("email") or {}).get("headers") or {}).get("subject")
    title = request.title or f"Forensic Case: {email_subject or email_doc.get('filename', 'Unknown')}"

    now = datetime.now(timezone.utc)
    inv_id = str(uuid4())

    notes = []
    if request.initial_note:
        notes.append({
            "id": str(uuid4()),
            "user_id": current_user["id"],
            "user_email": current_user.get("email"),
            "content": request.initial_note,
            "created_at": now,
        })

    audit_entry = {
        "action": "investigation_opened",
        "user_id": current_user["id"],
        "timestamp": now,
        "details": {"title": title, "email_id": request.email_id},
    }

    doc = {
        "_id": inv_id,
        "email_id": request.email_id,
        "user_id": current_user["id"],
        "title": title,
        "status": "open",
        "priority": request.priority,
        "tags": request.tags,
        "assigned_to": current_user.get("email"),
        "notes": notes,
        "audit_log": [audit_entry],
        "created_at": now,
        "updated_at": now,
    }

    await investigations_collection.insert_one(doc)

    doc["id"] = inv_id
    doc["email_summary"] = {
        "subject": email_subject,
        "filename": email_doc.get("filename"),
        "risk_score": (email_doc.get("risk_assessment") or {}).get("score", 0),
        "threat_band": (email_doc.get("scoring_details") or {}).get("band", "Low"),
    }
    return doc


@router.get("/", response_model=InvestigationListResponse)
async def list_investigations(
    status_filter: str | None = Query(default=None, alias="status"),
    priority_filter: str | None = Query(default=None, alias="priority"),
    limit: int = Query(default=20, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    current_user: dict[str, Any] = Depends(get_current_user),
):
    query: dict[str, Any] = {}
    if status_filter:
        query["status"] = status_filter
    if priority_filter:
        query["priority"] = priority_filter

    cursor = (
        investigations_collection.find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    items = []
    async for doc in cursor:
        doc["id"] = doc.pop("_id")
        items.append(doc)

    total = await investigations_collection.count_documents(query)

    return {
        "total": total,
        "limit": limit,
        "skip": skip,
        "investigations": items,
    }


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    doc = await investigations_collection.find_one({"_id": investigation_id})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    doc["id"] = doc.pop("_id")
    email_doc = await emails_collection.find_one({"_id": doc["email_id"]})
    if email_doc:
        doc["email_summary"] = {
            "subject": ((email_doc.get("email") or {}).get("headers") or {}).get("subject"),
            "filename": email_doc.get("filename"),
            "risk_score": (email_doc.get("risk_assessment") or {}).get("score", 0),
            "threat_band": (email_doc.get("scoring_details") or {}).get("band", "Low"),
        }
    return doc


@router.patch("/{investigation_id}", response_model=InvestigationResponse)
async def update_investigation(
    investigation_id: str,
    request: InvestigationUpdateRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    doc = await investigations_collection.find_one({"_id": investigation_id})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    updates: dict[str, Any] = {}
    audit_changes: dict[str, Any] = {}
    now = datetime.now(timezone.utc)

    if request.status is not None:
        updates["status"] = request.status
        audit_changes["status"] = request.status
    if request.priority is not None:
        updates["priority"] = request.priority
        audit_changes["priority"] = request.priority
    if request.tags is not None:
        updates["tags"] = request.tags
        audit_changes["tags"] = request.tags
    if request.assigned_to is not None:
        updates["assigned_to"] = request.assigned_to
        audit_changes["assigned_to"] = request.assigned_to

    if not updates:
        doc["id"] = doc.pop("_id")
        return doc

    updates["updated_at"] = now
    audit_entry = {
        "action": "investigation_updated",
        "user_id": current_user["id"],
        "timestamp": now,
        "details": audit_changes,
    }

    await investigations_collection.update_one(
        {"_id": investigation_id},
        {
            "$set": updates,
            "$push": {"audit_log": audit_entry},
        },
    )

    updated_doc = await investigations_collection.find_one({"_id": investigation_id})
    updated_doc["id"] = updated_doc.pop("_id")
    return updated_doc


@router.post("/{investigation_id}/notes", response_model=InvestigationNote)
async def add_investigation_note(
    investigation_id: str,
    request: InvestigationNoteRequest,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    doc = await investigations_collection.find_one({"_id": investigation_id})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    now = datetime.now(timezone.utc)
    note_id = str(uuid4())
    note_entry = {
        "id": note_id,
        "user_id": current_user["id"],
        "user_email": current_user.get("email"),
        "content": request.content,
        "created_at": now,
    }
    audit_entry = {
        "action": "note_added",
        "user_id": current_user["id"],
        "timestamp": now,
        "details": {"note_id": note_id},
    }

    await investigations_collection.update_one(
        {"_id": investigation_id},
        {
            "$push": {"notes": note_entry, "audit_log": audit_entry},
            "$set": {"updated_at": now},
        },
    )

    return note_entry


@router.get("/{investigation_id}/report")
async def get_investigation_report(
    investigation_id: str,
    current_user: dict[str, Any] = Depends(get_current_user),
):
    inv_doc = await investigations_collection.find_one({"_id": investigation_id})
    if not inv_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found.",
        )

    email_doc = await emails_collection.find_one({"_id": inv_doc["email_id"]})
    if not email_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referenced email analysis not found.",
        )

    return generate_forensic_report(inv_doc, email_doc)
