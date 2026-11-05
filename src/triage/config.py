"""Runtime settings (from environment variables) and the routing rules file.

Secrets are read only from the environment / .env file, are excluded from
repr() so they cannot leak into logs or tracebacks, and are never written to
the audit log.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from .models import ALLOWED_DESTINATIONS, Category, Priority

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES_PATH = PROJECT_ROOT / "config" / "triage_rules.json"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"
VALID_PROVIDERS = ("none", "anthropic", "openai")


class ConfigError(Exception):
    """Raised when settings or the rules file are invalid. Message is user-facing."""


# --------------------------------------------------------------------------- #
# Environment settings
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Settings:
    llm_provider: str = "none"
    llm_model: str | None = None
    llm_timeout_seconds: float = 20.0
    llm_max_attempts: int = 3
    rules_path: Path = DEFAULT_RULES_PATH
    audit_log_path: Path = Path("logs/audit.jsonl")
    log_level: str = "INFO"
    # repr=False keeps secrets out of logs, error messages and debugger output.
    webhook_token: str | None = field(default=None, repr=False)
    anthropic_api_key: str | None = field(default=None, repr=False)
    openai_api_key: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        if env is None:
            try:
                from dotenv import load_dotenv

                load_dotenv()  # does not override variables already set
            except ImportError:  # pragma: no cover - dotenv is a declared dependency
                pass
            env = os.environ

        def get(name: str) -> str | None:
            value = env.get(name)
            return value.strip() if value and value.strip() else None

        provider = (get("TRIAGE_LLM_PROVIDER") or "none").lower()
        if provider not in VALID_PROVIDERS:
            raise ConfigError(
                f"TRIAGE_LLM_PROVIDER must be one of {', '.join(VALID_PROVIDERS)} (got '{provider}')."
            )

        timeout = _parse_number(get("TRIAGE_LLM_TIMEOUT_SECONDS"), "TRIAGE_LLM_TIMEOUT_SECONDS", 20.0, float, 1, 120)
        attempts = _parse_number(get("TRIAGE_LLM_MAX_ATTEMPTS"), "TRIAGE_LLM_MAX_ATTEMPTS", 3, int, 1, 5)

        log_level = (get("TRIAGE_LOG_LEVEL") or "INFO").upper()
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ConfigError("TRIAGE_LOG_LEVEL must be DEBUG, INFO, WARNING or ERROR.")

        rules_path = Path(get("TRIAGE_RULES_PATH")) if get("TRIAGE_RULES_PATH") else DEFAULT_RULES_PATH

        return cls(
            llm_provider=provider,
            llm_model=get("TRIAGE_LLM_MODEL"),
            llm_timeout_seconds=timeout,
            llm_max_attempts=attempts,
            rules_path=rules_path,
            audit_log_path=Path(get("TRIAGE_AUDIT_LOG") or "logs/audit.jsonl"),
            log_level=log_level,
            webhook_token=get("TRIAGE_WEBHOOK_TOKEN"),
            anthropic_api_key=get("ANTHROPIC_API_KEY"),
            openai_api_key=get("OPENAI_API_KEY"),
        )


def _parse_number(raw, name, default, kind, low, high):
    if raw is None:
        return default
    try:
        value = kind(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number (got '{raw}').") from None
    if not (low <= value <= high):
        raise ConfigError(f"{name} must be between {low} and {high} (got {value}).")
    return value


# --------------------------------------------------------------------------- #
# Rules file
# --------------------------------------------------------------------------- #


class CategoryRule(BaseModel):
    destination: str
    base_priority: Priority
    keywords: list[str] = Field(default_factory=list)

    @field_validator("destination")
    @classmethod
    def _destination_allowed(cls, value: str) -> str:
        if value not in ALLOWED_DESTINATIONS:
            raise ValueError(
                f"destination '{value}' is not in the allowlist: {sorted(ALLOWED_DESTINATIONS)}"
            )
        return value

    @field_validator("keywords")
    @classmethod
    def _normalise_keywords(cls, value: list[str]) -> list[str]:
        return [kw.strip().lower() for kw in value if kw.strip()]


class ReviewRules(BaseModel):
    confidence_threshold: float = Field(ge=0.0, le=1.0)
    always_review_priorities: list[Priority] = Field(default_factory=list)
    always_review_categories: list[Category] = Field(default_factory=list)


class EscalationRules(BaseModel):
    to_p1: list[str] = Field(default_factory=list)
    raise_one_level: list[str] = Field(default_factory=list)


class RulesConfig(BaseModel):
    version: str
    notes: list[str] = Field(default_factory=list)
    review: ReviewRules
    categories: dict[Category, CategoryRule]
    escalation: EscalationRules = Field(default_factory=EscalationRules)

    @model_validator(mode="after")
    def _all_categories_present(self) -> "RulesConfig":
        missing = [c.value for c in Category if c not in self.categories]
        if missing:
            raise ValueError(f"rules file is missing categories: {missing}")
        return self


def load_rules(path: Path | str = DEFAULT_RULES_PATH) -> RulesConfig:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"Rules file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Rules file {path} is not valid JSON (line {exc.lineno}): {exc.msg}") from None
    try:
        return RulesConfig.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ConfigError(f"Rules file {path} is invalid: {problems}") from None
