"""Orchestrates one request: validate -> sanitize -> classify -> route -> audit."""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any

from pydantic import ValidationError

from .audit import AuditLogger, utc_now
from .classifier_llm import LLMClassifier, LLMError
from .classifier_rules import RuleBasedClassifier
from .config import RulesConfig, Settings, load_rules
from .models import Category, IntakeRequest, SecurityFlags, TriageResult
from .router import decide
from .sanitize import sanitize

log = logging.getLogger(__name__)


class IntakeValidationError(Exception):
    """Request failed schema validation. `errors` is safe to return to the caller."""

    def __init__(self, errors: list[dict[str, str]], request_id: str | None = None):
        self.errors = errors
        self.request_id = request_id
        super().__init__("; ".join(f"{e['field']}: {e['message']}" for e in errors))


def _validation_errors(exc: ValidationError) -> list[dict[str, str]]:
    # Deliberately omit the offending input value so it is not echoed back or logged.
    return [
        {"field": ".".join(str(p) for p in err["loc"]) or "(root)", "message": err["msg"]}
        for err in exc.errors()
    ]


class TriagePipeline:
    def __init__(
        self,
        rules: RulesConfig,
        audit: AuditLogger,
        llm: LLMClassifier | None = None,
    ):
        self.rules = rules
        self.audit = audit
        self.llm = llm
        self.rule_classifier = RuleBasedClassifier(rules)

    @property
    def classifier_name(self) -> str:
        return self.llm.name if self.llm else "rules"

    def process(self, raw: Any, default_channel: str = "webhook") -> TriageResult:
        request = self._validate(raw, default_channel)
        request_id = request.request_id or f"REQ-{uuid.uuid4().hex[:12]}"

        subject = sanitize(request.subject)
        description = sanitize(request.description)
        text = f"{subject.text}\n{description.text}"
        flags = SecurityFlags(
            pii_types=sorted(set(subject.pii_types + description.pii_types)),
            secret_redacted=subject.secret_redacted or description.secret_redacted,
            injection_indicators=sorted(set(subject.injection_indicators + description.injection_indicators)),
        )

        rules_result = self.rule_classifier.classify(text)
        classification = rules_result
        fallback_used = False
        fallback_reason: str | None = None
        disagreement = False

        if self.llm is not None:
            try:
                classification = self.llm.classify(text)
                disagreement = (
                    rules_result.category is not Category.unknown
                    and classification.category is not rules_result.category
                )
            except LLMError as exc:
                fallback_used = True
                fallback_reason = str(exc)
                log.warning("AI classifier failed for %s; using rule-based fallback: %s", request_id, exc)

        decision = decide(
            classification,
            text,
            flags,
            self.rules,
            fallback_used=fallback_used,
            classifier_disagreement=disagreement,
        )

        result = TriageResult(
            request_id=request_id,
            received_at=utc_now(),
            channel=request.channel,
            category=classification.category,
            priority=decision.priority,
            confidence=classification.confidence,
            destination=decision.destination,
            needs_human_review=decision.needs_human_review,
            review_reasons=decision.review_reasons,
            classifier_used=classification.classifier,
            fallback_used=fallback_used,
            fallback_reason=fallback_reason,
            rationale=classification.rationale,
            escalation_matches=decision.escalation_matches,
            security=flags,
            rules_version=self.rules.version,
        )

        self.audit.write(
            "triaged",
            {
                **result.model_dump(mode="json", exclude={"received_at"}),
                "rules_classifier_category": rules_result.category.value,
                "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "content_length": len(text),
            },
        )
        log.info(
            "Triaged %s -> %s %s %s (review=%s)",
            request_id,
            result.category.value,
            result.priority.value,
            result.destination,
            result.needs_human_review,
        )
        return result

    def _validate(self, raw: Any, default_channel: str) -> IntakeRequest:
        if not isinstance(raw, dict):
            errors = [{"field": "(root)", "message": "Each request must be a JSON object."}]
            self._audit_rejection(None, errors)
            raise IntakeValidationError(errors)
        data = dict(raw)
        data.setdefault("channel", default_channel)
        try:
            return IntakeRequest.model_validate(data)
        except ValidationError as exc:
            errors = _validation_errors(exc)
            rid = data.get("request_id") if isinstance(data.get("request_id"), str) else None
            # Only keep an ID that is itself well-formed; never log arbitrary input.
            if rid is not None and not (len(rid) <= 64 and rid.replace("-", "").replace("_", "").isalnum()):
                rid = None
            self._audit_rejection(rid, errors)
            raise IntakeValidationError(errors, rid) from None

    def _audit_rejection(self, request_id: str | None, errors: list[dict[str, str]]) -> None:
        self.audit.write("rejected", {"request_id": request_id, "errors": errors})
        log.info("Rejected request %s: %d validation error(s)", request_id or "(no id)", len(errors))


def build_pipeline(settings: Settings) -> TriagePipeline:
    from .classifier_llm import build_llm_classifier

    rules = load_rules(settings.rules_path)
    audit = AuditLogger(settings.audit_log_path)
    llm = build_llm_classifier(settings)
    return TriagePipeline(rules=rules, audit=audit, llm=llm)
