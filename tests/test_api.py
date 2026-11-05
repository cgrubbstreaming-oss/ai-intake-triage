import pytest
from fastapi.testclient import TestClient

from triage.api import MAX_BODY_BYTES, create_app
from triage.config import Settings

from conftest import valid_request


@pytest.fixture
def client(make_pipeline):
    return TestClient(create_app(settings=Settings(), pipeline=make_pipeline()))


@pytest.fixture
def token_client(make_pipeline):
    settings = Settings(webhook_token="test-token-123")
    return TestClient(create_app(settings=settings, pipeline=make_pipeline()))


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["classifier"] == "rules"


def test_form_page_is_served_with_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "<form" in response.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_valid_intake_returns_triage_result(client):
    response = client.post("/intake", json=valid_request())
    assert response.status_code == 200
    body = response.json()
    assert body["category"] == "technical_support"
    assert body["destination"] == "it_helpdesk"
    assert body["channel"] == "webhook"


def test_invalid_intake_returns_422_with_field_errors(client):
    response = client.post("/intake", json=valid_request(description="short"))
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "validation_failed"
    assert body["details"][0]["field"] == "description"


def test_malformed_json_returns_400(client):
    response = client.post("/intake", content=b"{not json", headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_json"


def test_oversized_body_returns_413(client):
    big = b'{"x": "' + b"a" * (MAX_BODY_BYTES + 10) + b'"}'
    response = client.post("/intake", content=big, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_token_required_when_configured(token_client):
    assert token_client.post("/intake", json=valid_request()).status_code == 401
    wrong = token_client.post("/intake", json=valid_request(), headers={"X-Webhook-Token": "wrong"})
    assert wrong.status_code == 401
    right = token_client.post("/intake", json=valid_request(), headers={"X-Webhook-Token": "test-token-123"})
    assert right.status_code == 200
