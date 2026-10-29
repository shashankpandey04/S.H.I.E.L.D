from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class EmailAnalysisRequest(BaseModel):
    include_body: bool = True
    include_attachments: bool = True


class EmailHeaders(BaseModel):
    subject: str | None = None
    from_: str | None = Field(default=None, alias="from")
    sender: list[str] = Field(default_factory=list)
    to: list[str] = Field(default_factory=list)
    recipient: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    bcc: list[str] = Field(default_factory=list)
    reply_to: list[str] = Field(default_factory=list)
    return_path: str | None = None
    date: str | None = None
    message_id: str | None = None
    received: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    type: str
    severity: str
    description: str | None = None
    evidence: str | None = None
    explanation: str | None = None


class URLAnalysisResult(BaseModel):
    url: str
    host: str | None = None
    status: str
    findings: list[Finding] = Field(default_factory=list)


class URLAnalysisSummary(BaseModel):
    total: int = 0
    suspicious_count: int = 0
    invalid_count: int = 0
    results: list[URLAnalysisResult] = Field(default_factory=list)


class RiskFinding(BaseModel):
    source: str
    type: str
    severity: str
    points: int
    description: str


class RiskAssessment(BaseModel):
    score: int
    category: str
    findings: list[RiskFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EmailAnalysisResponse(BaseModel):
    id: str
    filename: str
    sha256: str
    storage_path: str | None = None
    uploaded_at: datetime | str
    status: str
    user_id: str | None = None
    email: dict[str, Any]
    authentication: dict[str, Any]
    urls: dict[str, Any]
    url_analysis: dict[str, Any]
    header_analysis: dict[str, Any]
    risk_assessment: dict[str, Any]
    relay_analysis: dict[str, Any] = Field(default_factory=dict)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    scoring_details: dict[str, Any] = Field(default_factory=dict)
    subjective_logic: dict[str, Any] = Field(default_factory=dict)
    campaign_correlation: dict[str, Any] = Field(default_factory=dict)


class EmailListResponse(BaseModel):
    total: int
    limit: int
    skip: int
    emails: list[dict[str, Any]]
