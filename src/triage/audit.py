"""Append-only, hash-chained audit log (JSON Lines).

Each entry stores the SHA-256 of the previous entry, so editing or deleting a
line breaks the chain and `triage verify-log` reports where.

Minimal data: the log stores decisions and a hash of the (already redacted)
request text, never the request text itself.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


class AuditLogError(Exception):
    """The audit log could not be read or written. Requests fail closed."""


def _canonical(entry: dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(entry_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(entry_without_hash).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLogger:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.Lock()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditLogError(f"Cannot create audit log directory {self.path.parent}: {exc.strerror}") from None
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        try:
            lines = [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except OSError as exc:
            raise AuditLogError(f"Cannot read audit log {self.path}: {exc.strerror}") from None
        if not lines:
            return GENESIS_HASH
        try:
            return json.loads(lines[-1])["entry_hash"]
        except (json.JSONDecodeError, KeyError):
            raise AuditLogError(
                f"Last line of audit log {self.path} is corrupt. Run 'triage verify-log' to investigate."
            ) from None

    def write(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = {"timestamp": utc_now(), "event": event, **payload, "prev_hash": self._last_hash}
            entry["entry_hash"] = _hash(entry)
            try:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(_canonical(entry) + "\n")
            except OSError as exc:
                raise AuditLogError(f"Cannot write audit log {self.path}: {exc.strerror}") from None
            self._last_hash = entry["entry_hash"]
            return entry


def verify_chain(path: Path | str) -> tuple[bool, int, str]:
    """Return (ok, entries_checked, message)."""
    path = Path(path)
    if not path.exists():
        return False, 0, f"Audit log not found: {path}"
    previous = GENESIS_HASH
    count = 0
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, count, f"Line {line_no}: not valid JSON."
        stored = entry.pop("entry_hash", None)
        if entry.get("prev_hash") != previous:
            return False, count, f"Line {line_no}: prev_hash does not match the previous entry (entry removed or reordered?)."
        if stored != _hash(entry):
            return False, count, f"Line {line_no}: entry_hash mismatch (entry was modified)."
        previous = stored
        count += 1
    return True, count, f"OK: {count} entries, hash chain intact."
