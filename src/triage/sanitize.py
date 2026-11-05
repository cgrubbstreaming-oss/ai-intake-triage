"""Input hygiene: normalisation, sensitive-data redaction, and prompt-injection heuristics.

Redaction runs BEFORE classification, so neither the AI provider nor the audit
log ever receives the raw email addresses, phone numbers, card numbers,
SSNs or secrets that a requester pasted in.

These are heuristics, not guarantees. They reduce risk and raise flags for
human review; they do not make untrusted text safe.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Zero-width and bidi-control characters are a common way to hide text from humans.
_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")
# Control characters except tab (\x09) and newline (\x0a).
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_SECRET_KEY_VALUE = re.compile(
    r"\b(api[_-]?key|access[_-]?token|token|secret|password|passwd|pwd)(\s*[:=]\s*)\S+",
    re.IGNORECASE,
)
_SECRET_TOKENS = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")

INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}?\b(instructions|rules|prompt|guidelines)\b",
        re.IGNORECASE,
    ),
    "role_override": re.compile(
        r"\byou are now\b|\bact as\b|\bpretend to be\b|\bdeveloper mode\b|\bjailbreak\b",
        re.IGNORECASE,
    ),
    "system_prompt_probe": re.compile(
        r"\bsystem prompt\b|<\s*/?\s*(system|assistant|ticket)\s*>", re.IGNORECASE
    ),
    "priority_manipulation": re.compile(
        r"\b(set|change|make|raise|mark)\s+(the\s+|its\s+|this\s+)?priority\s+(to|as)\b",
        re.IGNORECASE,
    ),
    "routing_manipulation": re.compile(
        r"\b(route|send|assign|forward|escalate)\s+(this|it|me)(\s+(ticket|request))?\s+to\b",
        re.IGNORECASE,
    ),
    "classification_manipulation": re.compile(
        r"\b(classify|categori[sz]e)\s+(this|it)\b[^.\n]{0,20}\bas\b", re.IGNORECASE
    ),
}


@dataclass
class SanitizedText:
    text: str
    pii_types: list[str] = field(default_factory=list)
    secret_redacted: bool = False
    injection_indicators: list[str] = field(default_factory=list)


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub(" ", text)
    return text.strip()


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = int(char)
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def redact(text: str) -> tuple[str, list[str], bool]:
    """Return (redacted_text, pii_types_found, secret_found)."""
    found: list[str] = []
    secret_found = False

    def _kv(match: re.Match[str]) -> str:
        nonlocal secret_found
        secret_found = True
        return f"{match.group(1)}{match.group(2)}[REDACTED_SECRET]"

    text = _SECRET_KEY_VALUE.sub(_kv, text)
    if _SECRET_TOKENS.search(text):
        secret_found = True
        text = _SECRET_TOKENS.sub("[REDACTED_SECRET]", text)

    def _card(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            found.append("payment_card")
            return "[REDACTED_CARD]"
        return match.group(0)

    text = _CARD_CANDIDATE.sub(_card, text)

    for label, pattern, token in (
        ("ssn", _SSN, "[REDACTED_SSN]"),
        ("email", _EMAIL, "[REDACTED_EMAIL]"),
        ("phone", _PHONE, "[REDACTED_PHONE]"),
    ):
        if pattern.search(text):
            found.append(label)
            text = pattern.sub(token, text)

    return text, sorted(set(found)), secret_found


def detect_injection(text: str) -> list[str]:
    return [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(text)]


def sanitize(text: str) -> SanitizedText:
    cleaned = normalise(text)
    # Detect injection on the normalised (pre-redaction) text so hidden
    # characters cannot be used to split trigger phrases.
    indicators = detect_injection(cleaned)
    redacted, pii, secret = redact(cleaned)
    return SanitizedText(
        text=redacted, pii_types=pii, secret_redacted=secret, injection_indicators=indicators
    )
