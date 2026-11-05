"""Command-line interface.

  triage process data/samples/sample_requests.json [--output results/run.json] [--rules-only]
  triage verify-log [logs/audit.jsonl]
  triage serve [--host 127.0.0.1] [--port 8000]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from .audit import AuditLogError, verify_chain
from .config import ConfigError, Settings
from .logging_setup import configure_logging
from .pipeline import IntakeValidationError, build_pipeline

MAX_INPUT_BYTES = 5_000_000
MAX_RECORDS = 1000


def _load_records(path: Path) -> list:
    if not path.exists():
        raise ConfigError(f"Input file not found: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ConfigError(f"Input file is larger than {MAX_INPUT_BYTES} bytes.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON (line {exc.lineno}): {exc.msg}") from None
    if isinstance(data, dict) and isinstance(data.get("requests"), list):
        data = data["requests"]
    if not isinstance(data, list):
        raise ConfigError('Input must be a JSON list of requests, or {"requests": [...]}.')
    if len(data) > MAX_RECORDS:
        raise ConfigError(f"Input has {len(data)} records; the limit is {MAX_RECORDS}.")
    return data


def _print_table(results: list[dict]) -> None:
    header = f"{'REQUEST':<10} {'CATEGORY':<18} {'PRI':<4} {'DESTINATION':<27} {'CONF':<5} {'REVIEW':<6} REASONS"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r['request_id'][:10]:<10} {r['category']:<18} {r['priority']:<4} {r['destination']:<27} "
            f"{r['confidence']:<5} {'YES' if r['needs_human_review'] else 'no':<6} {', '.join(r['review_reasons'])}"
        )


def cmd_process(args: argparse.Namespace, settings: Settings) -> int:
    if args.rules_only:
        settings = dataclasses.replace(settings, llm_provider="none")
    pipeline = build_pipeline(settings)
    records = _load_records(Path(args.input))
    print(f"Classifier: {pipeline.classifier_name} | rules version: {pipeline.rules.version} | records: {len(records)}\n")

    results, rejected = [], []
    for index, record in enumerate(records, start=1):
        try:
            results.append(pipeline.process(record, default_channel="batch_file").model_dump(mode="json"))
        except IntakeValidationError as exc:
            rejected.append({"record": index, "request_id": exc.request_id, "errors": exc.errors})

    if results:
        _print_table(results)
    else:
        print("No records were triaged.")
    if rejected:
        print("\nRejected records:")
        for item in rejected:
            problems = "; ".join(f"{e['field']}: {e['message']}" for e in item["errors"])
            print(f"  #{item['record']} ({item['request_id'] or 'no id'}): {problems}")

    review = sum(1 for r in results if r["needs_human_review"])
    fallbacks = sum(1 for r in results if r["fallback_used"])
    print(
        f"\nSummary: {len(records)} records | {len(results)} triaged | {len(rejected)} rejected | "
        f"{review} flagged for human review | {fallbacks} AI fallbacks"
    )
    print(f"Audit log: {settings.audit_log_path}")

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"results": results, "rejected": rejected}, indent=2), encoding="utf-8")
        print(f"Results written to: {out}")
    return 1 if rejected else 0


def cmd_verify(args: argparse.Namespace, settings: Settings) -> int:
    ok, _count, message = verify_chain(args.path or settings.audit_log_path)
    print(message)
    return 0 if ok else 1


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    import uvicorn

    if args.host not in ("127.0.0.1", "localhost"):
        print(f"Warning: binding to {args.host} exposes the demo beyond this machine.", file=sys.stderr)
    uvicorn.run("triage.api:create_app", factory=True, host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="triage", description="AI intake and cybersecurity triage")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("process", help="Triage every request in a JSON file")
    p.add_argument("input")
    p.add_argument("--output", help="Write full JSON results to this path")
    p.add_argument("--rules-only", action="store_true", help="Ignore any AI provider settings")
    p.set_defaults(func=cmd_process)

    v = sub.add_parser("verify-log", help="Check the audit log hash chain")
    v.add_argument("path", nargs="?")
    v.set_defaults(func=cmd_verify)

    s = sub.add_parser("serve", help="Start the web form and webhook API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=cmd_serve)

    args = parser.parse_args(argv)
    try:
        settings = Settings.from_env()
        configure_logging(settings.log_level)
        return args.func(args, settings)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except AuditLogError as exc:
        print(f"Audit log error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
