# DevOps Agent (Strands Framework)

An AI-powered DevOps agent built with the [Strands](https://strandsagents.com/) framework.
The agent analyzes cloud infrastructure (GCP + AWS), surfaces security findings, and gives
Zero-Trust remediation guidance.

## Setup

1. Create a virtual environment: `python -m venv venv`
2. Activate it: `source venv/bin/activate` (macOS/Linux) or `.\venv\Scripts\activate` (Windows)
3. Install dependencies:

   ```bash
   pip install -r requirements.in            # runtime
   pip install -r requirements-dev.in        # dev (tests + lint)
   ```

   Or, if you use `pip-tools`:

   ```bash
   pip-compile requirements.in
   pip-compile requirements-dev.in --output-file=requirements-dev.txt
   pip-sync requirements.txt
   ```

4. Authenticate to Google Cloud via **Application Default Credentials** — avoid
   committing service account JSON keys to developer machines:

   ```bash
   gcloud auth application-default login
   gcloud config set project YOUR_PROJECT_ID
   ```

5. Copy `.env.example` to `.env` and adjust as needed (project id, region, log format).
6. (Optional) Configure AWS via `AWS_PROFILE` / `aws sso login` if you will use AWS tools.
7. Run the agent:

   ```bash
   python main.py                    # auto-resume last session
   python main.py --new-session      # start a fresh semantic session
   python main.py --list-sessions    # show known sessions and exit
   python main.py --session-id name  # pin an explicit id (overrides the above)
   ```

## LLM backend

The agent uses **Gemini via Vertex AI** by default — no API key required, authentication flows
through the ADC you already configured. Set in `.env`:

```bash
GOOGLE_GENAI_USE_VERTEXAI=true
GOOGLE_CLOUD_PROJECT=your-project
GOOGLE_CLOUD_LOCATION=us-east1
GEMINI_MODEL=gemini-2.5-flash      # optional override
```

Required one-time setup on the target project:

```bash
gcloud services enable aiplatform.googleapis.com --project=$GOOGLE_CLOUD_PROJECT
gcloud projects add-iam-policy-binding $GOOGLE_CLOUD_PROJECT \
  --member="user:you@example.com" --role="roles/aiplatform.user"
```

As a fallback you can set `GEMINI_API_KEY` instead (Google AI Studio consumer tier).

## Session management

The agent keeps conversation state under `~/.config/agent-devops/` (XDG-compliant;
overridable with `XDG_CONFIG_HOME`). On startup it:

- **Auto-generates a semantic id** like `alice-my-project-20260417` from the
  active `gcloud config` account + project + today's date. Falls back to
  `devops-<uuid>` when gcloud is not authenticated.
- **Auto-resumes the most recently used session** so you don't need to remember
  the id. Pass `--new-session` to force a fresh one (a numeric suffix is added
  if today's base id already exists).
- **Tracks session metadata** (`turn_count`, `last_used_at`, `gcp_user`,
  `gcp_project`) in `state.json`. `--list-sessions` prints the list with the
  current one marked `*`.

Inside the REPL:

- `sessions` → reprint the list without exiting.
- `mcp` → show which MCP servers are connected.
- `exit` / `quit` → end the session.

Set `DEVOPS_SESSION_ID` in your environment only when you need a stable,
shared label (e.g. CI fixtures, scripted scenarios).

## Terminal UI

Each turn is rendered with a live spinner that reflects the current phase
(`Thinking… → Running tool: X → Responding…`), followed by a summary table
of every tool invocation and a markdown panel with the agent's final answer.
Powered by [`rich`](https://github.com/Textualize/rich).

## Logging

Structured JSON logs to stderr, with automatic format selection:

- `LOG_FORMAT=auto` (default) — pretty colored lines in a TTY, JSON when piped
  or running in a non-interactive environment (Cloud Run, GKE, `docker logs`).
- `LOG_FORMAT=pretty` — force human format.
- `LOG_FORMAT=json` — force Cloud Logging shape.
- `LOG_LEVEL=DEBUG|INFO|WARNING|ERROR`
- `NO_COLOR=1` — disable ANSI colors in pretty mode.

## Features

- **GCP security tools** (one file per product under `tools/`):
  - `gcp_iam` — IAM bindings (primitive roles, user-managed SA keys).
  - `gcp_compute` — Compute Engine (public IPs, OS Login, Shielded VM, IP
    forwarding, project-wide SSH keys, default SA).
  - `gcp_storage` — Cloud Storage (public buckets, UBLA, PAP, CMEK, versioning,
    logging).
  - `gcp_cloudrun` — Cloud Run (allUsers invoker, IAP annotation, default SA,
    region).
  - `gcp_network` — VPC / firewall (`0.0.0.0/0` ingress, default VPC, firewall
    logging).
- **AWS tools**: S3 bucket encryption checks.
- **MCP integration**: `mcp-server-fetch` for web retrieval. The agent is
  instructed to fetch with `max_length=50000` and paginate at most once per URL
  to avoid truncation loops.
- **Smart error handling**: credentials / permissions / API-disabled errors are
  distinguished and produce actionable hints (e.g. `gcloud services enable X`).
- **Optional observability**: `OTEL_ENABLED=true` routes spans to Google Cloud
  Trace.

## Development

```bash
ruff check .
mypy tools/
pytest tests/ -v --cov=tools
```

Smoke test the GCP tools against a real project (no LLM):

```bash
venv/bin/python scripts/smoke_test_gcp.py YOUR_PROJECT_ID
```

## Security notes

- Never commit `gcp-credentials*.json`, `*-sa-key.json`,
  `application_default_credentials.json`, or any private keys. The `.gitignore`
  patterns are targeted; do not re-introduce a blanket `*.json` ignore.
- Tool findings follow a canonical schema (`severity`, `resource`, `category`,
  `message`, `recommendation`); do not fabricate findings or claims in LLM
  responses.
