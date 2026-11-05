import json

import pytest

from triage.classifier_rules import RuleBasedClassifier, confidence_from_scores, find_keywords
from triage.config import ConfigError, DEFAULT_RULES_PATH, load_rules
from triage.models import Category, ClassificationResult, Priority, SecurityFlags
from triage.router import decide, more_severe, raise_one_level


def test_keyword_match_is_whole_word():
    assert find_keywords("I need a refund", ["refund"]) == ["refund"]
    assert find_keywords("refunded already", ["refund"]) == []
    assert find_keywords("renamed with a .locked extension", [".locked"]) == [".locked"]


def test_confidence_scale():
    assert confidence_from_scores(0, 0) == 0.0
    assert confidence_from_scores(1, 0) == 0.55
    assert confidence_from_scores(2, 0) == 0.75
    assert confidence_from_scores(5, 1) == 0.95
    assert confidence_from_scores(2, 2) == 0.55  # tie lowers confidence


def test_tie_goes_to_earlier_security_category(rules):
    # one phishing keyword and one billing keyword
    result = RuleBasedClassifier(rules).classify("spoofed invoice")
    assert result.category is Category.phishing_report


def test_no_keywords_gives_unknown(rules):
    result = RuleBasedClassifier(rules).classify("hello there")
    assert result.category is Category.unknown
    assert result.confidence == 0.0


def test_priority_helpers():
    assert raise_one_level(Priority.P3) is Priority.P2
    assert raise_one_level(Priority.P1) is Priority.P1
    assert more_severe(Priority.P2, Priority.P4) is Priority.P2


def _classification(category=Category.technical_support, priority=Priority.P3, confidence=0.9, classifier="rules"):
    return ClassificationResult(category=category, priority=priority, confidence=confidence, classifier=classifier)


def test_escalation_floor_overrides_low_ai_priority(rules):
    # Even if a classifier says P4, ransomware language forces P1.
    decision = decide(_classification(Category.malware_suspected, Priority.P4), "ransomware on my pc", SecurityFlags(), rules)
    assert decision.priority is Priority.P1
    assert "priority_P1" in decision.review_reasons


def test_clean_request_needs_no_review(rules):
    decision = decide(_classification(), "vpn is slow", SecurityFlags(), rules)
    assert decision.destination == "it_helpdesk"
    assert decision.needs_human_review is False
    assert decision.review_reasons == []


@pytest.mark.parametrize(
    "kwargs, flags, expected_reason",
    [
        ({"confidence": 0.4}, SecurityFlags(), "low_confidence"),
        ({"category": Category.unknown}, SecurityFlags(), "category_unknown"),
        ({"category": Category.data_exposure}, SecurityFlags(), "sensitive_category"),
        ({}, SecurityFlags(injection_indicators=["ignore_instructions"]), "prompt_injection_suspected"),
        ({}, SecurityFlags(pii_types=["email"]), "pii_redacted"),
        ({}, SecurityFlags(secret_redacted=True), "secret_redacted"),
    ],
)
def test_review_triggers(rules, kwargs, flags, expected_reason):
    decision = decide(_classification(**kwargs), "some text", flags, rules)
    assert decision.needs_human_review is True
    assert expected_reason in decision.review_reasons


def test_fallback_and_disagreement_trigger_review(rules):
    decision = decide(_classification(), "text", SecurityFlags(), rules, fallback_used=True, classifier_disagreement=True)
    assert {"llm_fallback_used", "classifier_disagreement"} <= set(decision.review_reasons)


def test_rules_file_rejects_destination_outside_allowlist(tmp_path):
    data = json.loads(DEFAULT_RULES_PATH.read_text())
    data["categories"]["billing"]["destination"] = "https://attacker.example.com/hook"
    bad = tmp_path / "rules.json"
    bad.write_text(json.dumps(data))
    with pytest.raises(ConfigError, match="allowlist"):
        load_rules(bad)


def test_rules_file_missing_category_is_rejected(tmp_path):
    data = json.loads(DEFAULT_RULES_PATH.read_text())
    del data["categories"]["unknown"]
    bad = tmp_path / "rules.json"
    bad.write_text(json.dumps(data))
    with pytest.raises(ConfigError, match="missing categories"):
        load_rules(bad)


def test_missing_rules_file_gives_clear_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_rules(tmp_path / "nope.json")
