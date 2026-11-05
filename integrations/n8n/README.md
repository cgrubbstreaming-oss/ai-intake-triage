# Optional: n8n integration

This shows the triage service as one step in a no-code workflow. It's optional; the project is complete without it.

**Status: not yet built or tested.** The triage webhook it calls has been verified (see `docs/results_report.md`). Once you build and run the workflow, export it from n8n (**⋯ → Download**), save it as `integrations/n8n/triage_workflow.json`, and record the actual result in `docs/results_report.md`.

## Workflow

```
Webhook (n8n)  ->  HTTP Request: POST http://<host>:8000/intake  ->  IF needs_human_review
                                                                       ├─ true  -> "Human review queue" (e.g. Slack/email/Sheet)
                                                                       └─ false -> "Auto-routed" (e.g. Sheet row per destination)
```

## Steps

1. Start the triage API: `triage serve` (add `--host 0.0.0.0` only if n8n runs in Docker and must reach your machine).
2. In n8n, add a **Webhook** node (POST). It receives the intake JSON.
3. Add an **HTTP Request** node:
   - Method `POST`, URL `http://localhost:8000/intake` (from Docker, use `http://host.docker.internal:8000/intake`)
   - Send Body: JSON, using the incoming webhook body
   - If `TRIAGE_WEBHOOK_TOKEN` is set, add header `X-Webhook-Token` from an n8n credential (not hard-coded)
4. Add an **IF** node on `{{ $json.needs_human_review }}` is `true`.
5. Connect each branch to a destination node of your choice (for a demo, a **No Op** or **Google Sheets** node is enough).
6. Test with one of the requests in `data/samples/sample_requests.json`.

## Security notes

- Keep the webhook token in n8n's credential store, not in the workflow JSON.
- Check the exported workflow JSON for secrets before committing it.
