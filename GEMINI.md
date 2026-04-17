# Gemini Foundation Mandates

## Security first
- No secrets in code or logs. Use Google Application Default Credentials (`gcloud auth application-default login`) for local development; never commit service account JSON keys. The `.gitignore` patterns (`gcp-credentials*.json`, `*-sa-key.json`, `service-account*.json`) are intentional — do not widen them to blanket `*.json`.
- Apply the principle of least privilege: prefer predefined or custom IAM roles over primitives (`owner/editor/viewer`).
- Front Cloud Run services with IAP + Google Groups + FIDO2 2FA; never grant `allUsers` the invoker role.

## Python standards
- Idiomatic Python 3.11+. Type hints on all tool functions. Follow PEP 8; ruff enforces the formatting.
- Use `asyncio` for the agent loop in `main.py`; keep tool functions synchronous.
- Manage dependencies with `pip-tools` (`requirements.in` → `requirements.txt`).

## Tool contracts
- Every GCP tool in `tools/` returns a JSON string and uses the shared `Finding` schema from `tools/_common.py`.
- When a tool fails, return a structured error envelope with an actionable `hint` (see `tools._common.handle_gcp_exception`).

## Cloud best practices
- Reference GCP Zero-Trust security best practices when proposing changes: IAP-gated ingress, CMEK for regulated data, Shielded VM enabled, OS Login enforced.
- Primary region: `us-east1`; Artifact Registry: `southamerica-west1`.
- Observability: JSON logs via `logging_config.configure_logging()`; optional Cloud Trace via `OTEL_ENABLED=true`.
