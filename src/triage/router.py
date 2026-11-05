"""Deterministic routing and human-review decisions.

The classifier proposes (category, priority, confidence). This module decides
the destination and whether a person must look at it. Keeping this logic out
of the AI means prompt-injected text cannot change where a request goes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .classifier_rules import find_keywords
from .config import RulesConfig
from .models import Category, ClassificationResult, Priority, SecurityFlags

_ORDER = [Priority.P1, Priority.P2, Priority.P3, Priority.P4]


def raise_one_level(priority: Priority) -> Priority:
    index = _ORDER.index(priority)
    return _ORDER[max(0, index - 1)]


def more_severe(a: Priority, b: Priority) -> Priority:
    return a if _ORDER.index(a) <= _ORDER.index(b) else b


@dataclass
class RoutingDecision:
    destination: str
    priority: Priority
    needs_human_review: bool
    review_reasons: list[str] = field(default_factory=list)
    escalation_matches: list[str] = field(default_factory=list)


def apply_escalation(priority: Priority, text: str, rules: RulesConfig) -> tuple[Priority, list[str]]:
    p1_hits = find_keywords(text, rules.escalation.to_p1)
    raise_hits = find_keywords(text, rules.escalation.raise_one_level)
    if raise_hits:
        priority = raise_one_level(priority)
    if p1_hits:
        priority = Priority.P1
    return priority, p1_hits + raise_hits


def decide(
    classification: ClassificationResult,
    text: str,
    flags: SecurityFlags,
    rules: RulesConfig,
    *,
    fallback_used: bool = False,
    classifier_disagreement: bool = False,
) -> RoutingDecision:
    priority, escalations = apply_escalation(classification.priority, text, rules)
    destination = rules.categories[classification.category].destination

    reasons: list[str] = []
    if priority in rules.review.always_review_priorities:
        reasons.append(f"priority_{priority.value}")
    if classification.category is Category.unknown:
        reasons.append("category_unknown")
    if classification.category in rules.review.always_review_categories:
        reasons.append("sensitive_category")
    if classification.confidence < rules.review.confidence_threshold:
        reasons.append("low_confidence")
    if flags.injection_suspected:
        reasons.append("prompt_injection_suspected")
    if flags.pii_types:
        reasons.append("pii_redacted")
    if flags.secret_redacted:
        reasons.append("secret_redacted")
    if fallback_used:
        reasons.append("llm_fallback_used")
    if classifier_disagreement:
        reasons.append("classifier_disagreement")

    return RoutingDecision(
        destination=destination,
        priority=priority,
        needs_human_review=bool(reasons),
        review_reasons=reasons,
        escalation_matches=escalations,
    )
