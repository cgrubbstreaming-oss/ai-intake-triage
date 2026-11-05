import json
from pathlib import Path

import pytest

from triage.audit import AuditLogger
from triage.config import DEFAULT_RULES_PATH, load_rules
from triage.pipeline import TriagePipeline

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "data" / "samples"


@pytest.fixture
def rules():
    return load_rules(DEFAULT_RULES_PATH)


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


@pytest.fixture
def make_pipeline(rules, audit_path):
    def _make(llm=None):
        return TriagePipeline(rules=rules, audit=AuditLogger(audit_path), llm=llm)

    return _make


@pytest.fixture
def sample_requests():
    return json.loads((SAMPLES_DIR / "sample_requests.json").read_text())["requests"]


@pytest.fixture
def invalid_requests():
    return json.loads((SAMPLES_DIR / "invalid_requests.json").read_text())


def valid_request(**overrides):
    base = {
        "request_id": "T-1",
        "subject": "VPN keeps disconnecting",
        "description": "The VPN drops every few minutes when working from home.",
    }
    base.update(overrides)
    return base
