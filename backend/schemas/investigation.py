from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

InvestigationStatus = Literal["open", "in_progress", "closed", "archived"]
InvestigationPriority = Literal["low", "medium", "high", "critical"]


class InvestigationCreateRequest(BaseModel):
    email_id: str
    title: str | None = Field(default=None, max_length=200)
    priority: InvestigationPriority = "medium"
    tags: list[str] = Field(default_factory=list)
    initial_note: str | None = Field(default=None, max_length=2000)


class InvestigationUpdateRequest(BaseModel):
    status: InvestigationStatus | None = None
    priority: InvestigationPriority | None = None
    tags: list[str] | None = None
    assigned_to: str | None = None


class InvestigationNoteRequest(BaseModel):
    content: str = Field(min_length=1, max_length=4000)


class InvestigationNote(BaseModel):
    id: str
    user_id: str
    user_email: str | None = None
    content: str
    created_at: datetime | str


class AuditLogEntry(BaseModel):
    action: str
    user_id: str
    timestamp: datetime | str
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationResponse(BaseModel):
    id: str
    email_id: str
    user_id: str
    title: str
    status: InvestigationStatus
    priority: InvestigationPriority
    tags: list[str]
    assigned_to: str | None = None
    notes: list[InvestigationNote] = Field(default_factory=list)
    audit_log: list[AuditLogEntry] = Field(default_factory=list)
    email_summary: dict[str, Any] | None = None
    created_at: datetime | str
    updated_at: datetime | str


class InvestigationListResponse(BaseModel):
    total: int
    limit: int
    skip: int
    investigations: list[InvestigationResponse]
