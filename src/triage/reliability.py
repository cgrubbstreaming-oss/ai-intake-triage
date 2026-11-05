"""Retry with exponential backoff for transient failures.

Implemented here (rather than relying on SDK defaults) so the behaviour is
visible, logged, configurable and unit-tested.
"""

from __future__ import annotations

import logging
import random
import time
from typing import Callable, TypeVar

T = TypeVar("T")
log = logging.getLogger(__name__)

RETRYABLE_STATUS_CODES = frozenset({408, 409, 429, 500, 502, 503, 504, 529})
RETRYABLE_ERROR_NAMES = frozenset({"APITimeoutError", "APIConnectionError"})


def is_retryable_error(exc: BaseException) -> bool:
    """Transient = worth retrying. Auth errors, bad requests and bad output are not."""
    if isinstance(exc, (TimeoutError, ConnectionError)):
        return True
    if type(exc).__name__ in RETRYABLE_ERROR_NAMES:
        return True
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and status in RETRYABLE_STATUS_CODES


def retry_call(
    fn: Callable[[], T],
    *,
    max_attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    is_retryable: Callable[[BaseException], bool] = is_retryable_error,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except Exception as exc:
            if attempt >= max_attempts or not is_retryable(exc):
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            delay *= random.uniform(0.8, 1.2)  # jitter avoids synchronized retries
            log.warning(
                "Attempt %d/%d failed with %s; retrying in %.2fs",
                attempt,
                max_attempts,
                type(exc).__name__,
                delay,
            )
            sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover
