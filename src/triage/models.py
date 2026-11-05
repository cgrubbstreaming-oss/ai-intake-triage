"""Data contracts for the triage pipeline.

Every piece of data that enters or leaves the system passes through one of
these Pydantic models, so invalid input is rejected at the boundary with a
clear message instead of failing somewhere deep in the pipeline.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Channel(str, Enum):
    web_form = "web_form"
    webhook = "webhook"
    email = "email"
    chat = "chat"
    batch_file = "batch_file"


class Category(str, Enum):
    malware_suspected = "malware_suspected"
    data_exposure = "data_exposure"
    phishing_report = "phishing_report"
    account_access = "account_access"
    access_request = "access_request"
    technical_support = "technical_support"
    billing = "billing"
    general_inquiry = "general_inquiry"
    unknown = "unknown"


CATEGORY_DESCRIPTIONS: dict[Category, str] = {
    Category.malware_suspected: "possible malware, ransomware, virus, or unexpected encrypted/renamed files",
    Category.data_exposure: "sensitive data sent, shared, lost, or exposed to the wrong party",
    Category.phishing_report: "suspicious or spoofed email, message, or link; possible credential theft",
    Category.account_access: "locked out, password reset, MFA or sign-in problems",
    Category.access_request: "request for new access, permissions, or accounts",
    Category.technical_support: "hardware, software, network, or device problems",
    Category.billing: "charges, invoices, refunds, payments, subscriptions",
    Category.general_inquiry: "general questions or information requests",
    Category.unknown: "not enough information to decide",
}


class Priority(str, Enum):
    """P1 is most severe. Comparison helpers live in router.py."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


# The only places a request can ever be routed. The rules file is validated
# against this list at startup, and the AI classifier never picks a destination.
ALLOWED_DESTINATIONS: frozenset[str] = frozenset(
    {
        "security_incident_response",
        "identity_access_team",
        "it_helpdesk",
        "billing_team",
        "general_support_queue",
        "human_triage",
    }
)


class IntakeRequest(BaseModel):
    """A single inbound request.

    Minimal data collection: there are deliberately no name, email, or phone
    fields, and extra="forbid" rejects any field not listed here.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    request_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")
    channel: Channel = Channel.webhook
    subject: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=10, max_length=5000)
    requester_role: Literal["employee", "customer", "contractor", "unknown"] = "unknown"
    affected_systems: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("affected_systems")
    @classmethod
    def _check_systems(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        for item in cleaned:
            if len(item) > 100:
                raise ValueError("each affected system name must be 100 characters or fewer")
        return cleaned


class ClassificationResult(BaseModel):
    """What a classifier (rules or AI) is allowed to decide."""

    model_config = ConfigDict(extra="ignore")

    category: Category
    priority: Priority
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""
    classifier: str = "rules"

    @field_validator("rationale", mode="before")
    @classmethod
    def _truncate_rationale(cls, value: object) -> str:
        text = "" if value is None else str(value)
        return text[:300]


class SecurityFlags(BaseModel):
    pii_types: list[str] = Field(default_factory=list)
    secret_redacted: bool = False
    injection_indicators: list[str] = Field(default_factory=list)

    @property
    def injection_suspected(self) -> bool:
        return bool(self.injection_indicators)


class TriageResult(BaseModel):
    request_id: str
    received_at: str
    channel: Channel
    category: Category
    priority: Priority
    confidence: float
    destination: str
    needs_human_review: bool
    review_reasons: list[str]
    classifier_used: str
    fallback_used: bool
    fallback_reason: str | None = None
    rationale: str
    escalation_matches: list[str]
    security: SecurityFlags
    rules_version: str
