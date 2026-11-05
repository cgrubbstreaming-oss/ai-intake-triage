"""Deterministic keyword classifier.

This is the non-AI fallback, and also the baseline the AI result is compared
against. It is intentionally simple and explainable: every decision lists the
keywords that produced it.
"""

from __future__ import annotations

import re
from functools import lru_cache

from .config import RulesConfig
from .models import Category, ClassificationResult


@lru_cache(maxsize=1024)
def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    # Whole-word/phrase match that also works for keywords starting with
    # punctuation such as ".locked".
    return re.compile(r"(?<!\w)" + re.escape(keyword) + r"(?!\w)")


def find_keywords(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    return [kw for kw in keywords if _keyword_pattern(kw).search(lowered)]


def confidence_from_scores(top: int, runner_up: int) -> float:
    if top == 0:
        return 0.0
    confidence = 0.35 + 0.2 * min(top, 3)  # 1 hit -> 0.55, 2 -> 0.75, 3+ -> 0.95
    if runner_up == top:
        confidence -= 0.2  # ambiguous: another category matched equally well
    return round(max(0.0, min(confidence, 0.95)), 2)


class RuleBasedClassifier:
    name = "rules"

    def __init__(self, rules: RulesConfig):
        self.rules = rules

    def classify(self, text: str) -> ClassificationResult:
        scores: list[tuple[Category, list[str]]] = []
        for category, rule in self.rules.categories.items():
            if category is Category.unknown:
                continue
            scores.append((category, find_keywords(text, rule.keywords)))

        # Stable sort keeps rules-file order on ties (security categories first).
        ranked = sorted(scores, key=lambda item: len(item[1]), reverse=True)
        best_category, best_hits = ranked[0]
        runner_up = len(ranked[1][1]) if len(ranked) > 1 else 0

        if not best_hits:
            unknown_rule = self.rules.categories[Category.unknown]
            return ClassificationResult(
                category=Category.unknown,
                priority=unknown_rule.base_priority,
                confidence=0.0,
                rationale="No category keywords matched.",
                classifier=self.name,
            )

        rule = self.rules.categories[best_category]
        return ClassificationResult(
            category=best_category,
            priority=rule.base_priority,
            confidence=confidence_from_scores(len(best_hits), runner_up),
            rationale=f"Matched keywords: {', '.join(best_hits)}",
            classifier=self.name,
        )
