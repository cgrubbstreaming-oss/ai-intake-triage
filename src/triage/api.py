"""HTTP interface: a webhook endpoint (POST /intake) and a small HTML form.

Run with:  triage serve      (binds to 127.0.0.1 by default)
"""

from __future__ import annotations

import hmac
import json
import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from . import __version__
from .audit import AuditLogError
from .config import PROJECT_ROOT, Settings
from .logging_setup import configure_logging
from .pipeline import IntakeValidationError, TriagePipeline, build_pipeline

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 20_000
FORM_PATH = PROJECT_ROOT / "templates" / "form.html"


def _error(status: int, code: str, message: str, **extra) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": code, "message": message, **extra})


def create_app(settings: Settings | None = None, pipeline: TriagePipeline | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    configure_logging(settings.log_level)
    pipeline = pipeline or build_pipeline(settings)

    app = FastAPI(
        title="AI Intake & Cybersecurity Triage",
        version=__version__,
        description="Simulated-data demo. Do not submit real personal data.",
    )
    app.state.pipeline = pipeline

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        reference = uuid.uuid4().hex[:12]
        log.exception("Unhandled error (reference %s)", reference)
        # No stack trace or internal detail is returned to the caller.
        return _error(500, "internal_error", "Unexpected server error.", reference=reference)

    @app.get("/", response_class=HTMLResponse)
    def form() -> HTMLResponse:
        return HTMLResponse(Path(FORM_PATH).read_text(encoding="utf-8"))

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "classifier": pipeline.classifier_name, "rules_version": pipeline.rules.version}

    @app.post("/intake")
    async def intake(request: Request, x_webhook_token: str | None = Header(default=None)):
        if settings.webhook_token:
            supplied = x_webhook_token or ""
            if not hmac.compare_digest(supplied.encode(), settings.webhook_token.encode()):
                return _error(401, "unauthorized", "Missing or invalid X-Webhook-Token header.")

        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            return _error(413, "payload_too_large", f"Request body must be under {MAX_BODY_BYTES} bytes.")
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return _error(413, "payload_too_large", f"Request body must be under {MAX_BODY_BYTES} bytes.")

        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _error(400, "invalid_json", "Request body must be valid JSON.")

        try:
            result = await run_in_threadpool(pipeline.process, payload, "webhook")
        except IntakeValidationError as exc:
            return _error(422, "validation_failed", "Request did not pass validation.", details=exc.errors)
        except AuditLogError as exc:
            log.error("Audit log unavailable: %s", exc)
            # Fail closed: no decision is returned unless it was recorded.
            return _error(503, "audit_unavailable", "Request not processed because the audit log is unavailable.")
        return result.model_dump(mode="json")

    return app
