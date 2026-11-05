"""Application logging (operational logs, separate from the audit log).

Ticket text and API keys are never passed to the logger anywhere in the code.
"""

from __future__ import annotations

import logging


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    # The HTTP client libraries log full request URLs at DEBUG; keep them quiet.
    for noisy in ("httpx", "httpcore", "httpx2", "httpcore2", "anthropic", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
