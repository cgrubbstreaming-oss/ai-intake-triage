import pytest
from pydantic import ValidationError

from triage.models import IntakeRequest

from conftest import valid_request


def test_valid_request_is_accepted():
    req = IntakeRequest.model_validate(valid_request())
    assert req.subject == "VPN keeps disconnecting"
    assert req.requester_role == "unknown"


def test_unexpected_personal_field_is_rejected():
    with pytest.raises(ValidationError) as exc:
        IntakeRequest.model_validate(valid_request(email="someone@example.com"))
    assert exc.value.errors()[0]["loc"] == ("email",)


@pytest.mark.parametrize(
    "overrides",
    [
        {"description": "short"},
        {"subject": "x" * 201},
        {"description": "x" * 5001},
        {"request_id": "has spaces!"},
        {"requester_role": "ceo"},
        {"affected_systems": ["x" * 101]},
        {"affected_systems": [f"s{i}" for i in range(11)]},
    ],
)
def test_invalid_values_are_rejected(overrides):
    with pytest.raises(ValidationError):
        IntakeRequest.model_validate(valid_request(**overrides))


def test_whitespace_is_stripped():
    req = IntakeRequest.model_validate(valid_request(subject="   VPN down   "))
    assert req.subject == "VPN down"
