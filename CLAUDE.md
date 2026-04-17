# Claude Foundation Mandates

## Security
- **No hardcoded credentials.** Use Application Default Credentials (`gcloud auth application-default login`) locally; never commit JSON key files. The `.gitignore` blocks `gcp-credentials*.json`, `*-sa-key.json`, `service-account*.json`, `application_default_credentials.json` — do not re-introduce a blanket `*.json` pattern.
- Follow Zero-Trust principles: least privilege IAM, IAP-protected ingress, no default service accounts, no primitive roles (`roles/owner|editor|viewer`) on humans.
- Never log secrets, API keys, or full IAM policies to structured logs.

## Python conventions
- PEP 8 + type hints on all public functions (`mypy tools/` must pass with `disallow_untyped_defs`).
- Async/await only where I/O is involved (`main.py`); tool functions stay sync — Strands supports both.
- Keep line length under 100 (ruff config).
- Dependency management via `pip-tools`: `requirements.in` is the source of truth; regenerate `requirements.txt` with `pip-compile`.

## Tool design
- All GCP tools live under `tools/` as one file per GCP product.
- Every tool returns a **JSON string** (never a Python dict) produced via `tools._common.as_tool_result(...)` on success or `error_result(...)` on failure.
- Every finding uses the `Finding` dataclass with fields `severity`, `resource`, `category`, `message`, `recommendation` (+ optional `metadata`). No ad-hoc shapes.
- Wrap exceptions through `tools._common.handle_gcp_exception(...)` so credentials / permissions / not-found errors become actionable messages instead of tracebacks.

## Observability
- Use `logging.getLogger(__name__)`; never `print()` for telemetry (interactive CLI prompts in `main.py` may keep `print`).
- Enable tracing on demand via `OTEL_ENABLED=true`; the `traced_tool` decorator adds spans when tracing is active, no-ops otherwise.

## GCP architecture defaults
- Primary region: `us-east1` (Virginia).
- Artifact Registry region: `southamerica-west1` (configurable in `tools/_common.py`).
- Cloud Run services must enable IAP (`--iap` flag) and never bind `allUsers` to `roles/run.invoker`.
- Cloud Storage buckets must enable Uniform Bucket-Level Access and `publicAccessPrevention=enforced`.
