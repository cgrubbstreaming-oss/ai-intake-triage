# Security considerations

This is a demonstration project that uses simulated data. The controls below reduce risk; they are not a substitute for a security review before handling real data.

## Controls implemented

| Area | Control | Where |
|---|---|---|
| Input validation | Strict Pydantic schema, length limits, allowed values, unknown fields rejected | `models.py` |
| Minimal data collection | No name/email/phone fields; extra fields rejected | `models.py` |
| Request limits | 20 KB HTTP body cap; 5 MB / 1000-record batch cap | `api.py`, `cli.py` |
| Sensitive data | Emails, phone numbers, Luhn-valid card numbers, SSNs and common secret formats are redacted before classification, AI calls and logging | `sanitize.py` |
| Prompt injection | Heuristic detection (instruction override, role override, priority/routing manipulation, tag injection); hidden Unicode characters stripped; ticket wrapped in delimiters; AI cannot choose a destination; detections force human review | `sanitize.py`, `classifier_llm.py`, `router.py` |
| AI output handling | JSON parsed and validated against enum allowlists; invalid output triggers fallback | `classifier_llm.py` |
| Secrets | Keys only from environment / `.env` (gitignored); excluded from `repr`; never logged; `.env.example` contains no values | `config.py`, `.gitignore` |
| Authentication | Optional `X-Webhook-Token` shared secret, compared in constant time | `api.py` |
| Error handling | Validation errors list fields without echoing input; unexpected errors return a reference ID, not a stack trace | `pipeline.py`, `api.py` |
| Audit | Hash-chained append-only log; tampering detectable with `triage verify-log`; fails closed | `audit.py` |
| Network exposure | Server binds to 127.0.0.1 by default | `cli.py` |
| HTTP headers | `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `no-store` | `api.py` |
| Front end | Results rendered with `textContent` (no `innerHTML`) | `templates/form.html` |

## Known limitations

- Regex redaction misses PII in unexpected formats (international phone numbers, names, addresses).
- Injection detection is pattern-based and can be evaded by rephrasing. The main defence is architectural: the AI can't change routing.
- The audit hash chain detects edits but doesn't prevent someone with file access from rewriting the whole log. Production would ship entries to write-once storage or sign them.
- The content hash in the audit log is a SHA-256 of redacted text. Short, predictable texts could be guessed by brute force.
- A shared-secret token is not user authentication. There is no rate limiting, TLS termination or role-based access.
- When the AI provider is enabled, redacted ticket text is sent to a third party. Check the provider's data-retention terms before using real data.
