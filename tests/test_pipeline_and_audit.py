import json

import pytest

from triage.audit import AuditLogError, AuditLogger, verify_chain
from triage.pipeline import IntakeValidationError

from conftest import valid_request

# Expected rules-only outcome for every simulated request in data/samples/sample_requests.json.
# (category, priority, destination, needs_review, reasons that must be present)
EXPECTED = {
    "SIM-001": ("phishing_report", "P2", "security_incident_response", False, []),
    "SIM-002": ("malware_suspected", "P1", "security_incident_response", True, ["priority_P1"]),
    "SIM-003": ("data_exposure", "P2", "security_incident_response", True, ["sensitive_category"]),
    "SIM-004": ("account_access", "P3", "identity_access_team", False, []),
    "SIM-005": ("access_request", "P4", "identity_access_team", False, []),
    "SIM-006": ("technical_support", "P3", "it_helpdesk", False, []),
    "SIM-007": ("billing", "P4", "billing_team", False, []),
    "SIM-008": ("general_inquiry", "P4", "general_support_queue", False, []),
    "SIM-009": ("technical_support", "P3", "it_helpdesk", True, ["prompt_injection_suspected"]),
    "SIM-010": ("billing", "P4", "billing_team", True, ["pii_redacted"]),
    "SIM-011": ("unknown", "P3", "human_triage", True, ["category_unknown", "low_confidence"]),
    "SIM-012": ("phishing_report", "P1", "security_incident_response", True, ["priority_P1"]),
    "SIM-013": ("technical_support", "P3", "it_helpdesk", True, ["secret_redacted"]),
}


def test_every_sample_has_an_expectation(sample_requests):
    assert {r["request_id"] for r in sample_requests} == set(EXPECTED)


@pytest.mark.parametrize("request_id", sorted(EXPECTED))
def test_sample_request_is_triaged_as_expected(make_pipeline, sample_requests, request_id):
    record = next(r for r in sample_requests if r["request_id"] == request_id)
    category, priority, destination, review, reasons = EXPECTED[request_id]
    result = make_pipeline().process(record)
    assert result.category.value == category
    assert result.priority.value == priority
    assert result.destination == destination
    assert result.needs_human_review is review
    for reason in reasons:
        assert reason in result.review_reasons


def test_invalid_samples_are_all_rejected(make_pipeline, invalid_requests):
    pipeline = make_pipeline()
    for record in invalid_requests:
        with pytest.raises(IntakeValidationError):
            pipeline.process(record)


def test_validation_errors_do_not_echo_input(make_pipeline):
    with pytest.raises(IntakeValidationError) as exc:
        make_pipeline().process(valid_request(email="leak@example.com"))
    assert "leak@example.com" not in json.dumps(exc.value.errors)


def test_missing_request_id_is_generated(make_pipeline):
    record = valid_request()
    del record["request_id"]
    assert make_pipeline().process(record).request_id.startswith("REQ-")


def test_audit_log_has_decisions_but_not_raw_text(make_pipeline, audit_path, sample_requests):
    pipeline = make_pipeline()
    for record in sample_requests:
        pipeline.process(record)
    content = audit_path.read_text()
    lines = content.splitlines()
    assert len(lines) == len(sample_requests)
    first = json.loads(lines[0])
    assert first["event"] == "triaged"
    assert {"category", "priority", "destination", "content_sha256", "entry_hash", "prev_hash"} <= first.keys()
    # No raw ticket text or PII ends up in the log.
    assert "jane.doe@example.com" not in content
    assert "4111 1111 1111 1111" not in content
    assert "sk-test1234567890" not in content
    assert "fake login page" not in content


def test_rejections_are_audited(make_pipeline, audit_path):
    with pytest.raises(IntakeValidationError):
        make_pipeline().process(valid_request(description="short"))
    entry = json.loads(audit_path.read_text().splitlines()[-1])
    assert entry["event"] == "rejected"
    assert entry["errors"][0]["field"] == "description"


def test_hash_chain_verifies(make_pipeline, audit_path, sample_requests):
    pipeline = make_pipeline()
    for record in sample_requests[:3]:
        pipeline.process(record)
    ok, count, _ = verify_chain(audit_path)
    assert ok and count == 3


def test_hash_chain_detects_modification(make_pipeline, audit_path, sample_requests):
    pipeline = make_pipeline()
    for record in sample_requests[:3]:
        pipeline.process(record)
    lines = audit_path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["priority"] = "P4"  # someone quietly downgrades a decision
    lines[1] = json.dumps(entry)
    audit_path.write_text("\n".join(lines) + "\n")
    ok, _, message = verify_chain(audit_path)
    assert not ok
    assert "Line 2" in message


def test_hash_chain_detects_deletion(make_pipeline, audit_path, sample_requests):
    pipeline = make_pipeline()
    for record in sample_requests[:3]:
        pipeline.process(record)
    lines = audit_path.read_text().splitlines()
    audit_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _, message = verify_chain(audit_path)
    assert not ok
    assert "prev_hash" in message


def test_chain_continues_across_restarts(rules, audit_path, sample_requests):
    from triage.pipeline import TriagePipeline

    TriagePipeline(rules, AuditLogger(audit_path)).process(sample_requests[0])
    TriagePipeline(rules, AuditLogger(audit_path)).process(sample_requests[1])
    ok, count, _ = verify_chain(audit_path)
    assert ok and count == 2


def test_corrupt_audit_log_fails_closed(audit_path):
    audit_path.write_text("this is not json\n")
    with pytest.raises(AuditLogError, match="corrupt"):
        AuditLogger(audit_path)
