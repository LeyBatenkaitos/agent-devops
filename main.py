"""CLI entrypoint for the DevOps agent (Strands framework).

Run locally with ADC-authenticated Google credentials:

    gcloud auth application-default login
    python main.py                       # auto-resume last session
    python main.py --new-session         # start a fresh semantic session
    python main.py --list-sessions       # show known sessions
    python main.py --session-id custom   # explicit id (overrides everything)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from mcp.client.stdio import StdioServerParameters, stdio_client
from strands import Agent
from strands.tools.mcp import MCPClient

from logging_config import configure_logging
from memory import get_session_manager
from observability import configure_tracing
from sessions import (
    format_session_list,
    increment_turn,
    load_state,
    register_session,
    resolve_session_id,
)
from ui import AgentUI

from tools.aws import analyze_aws_infra, check_s3_encryption
from tools.gcp_cloudrun import scan_cloudrun_services
from tools.gcp_compute import analyze_gcp_infra
from tools.gcp_iam import audit_gcp_service_account_keys, scan_gcp_iam_roles
from tools.gcp_network import scan_gcp_network
from tools.gcp_storage import scan_gcs_buckets

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


def _build_gemini_model():
    """Build a Strands GeminiModel backed by Vertex AI (Zero-Trust default).

    Uses Application Default Credentials — no API keys. Honors the same
    GOOGLE_CLOUD_PROJECT / GOOGLE_CLOUD_LOCATION env vars that the rest of the
    GCP tooling uses. Falls back to the public Gemini API when
    ``GOOGLE_GENAI_USE_VERTEXAI`` is not set to ``true`` and
    ``GEMINI_API_KEY`` is present.
    """

    from google import genai
    from strands.models.gemini import GeminiModel

    model_id = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "").lower() == "true"

    if use_vertex:
        project = os.environ.get("GOOGLE_CLOUD_PROJECT")
        location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-east1")
        if not project:
            raise RuntimeError(
                "GOOGLE_GENAI_USE_VERTEXAI=true but GOOGLE_CLOUD_PROJECT is not set."
            )
        client = genai.Client(vertexai=True, project=project, location=location)
        return GeminiModel(client=client, model_id=model_id)

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "No LLM backend configured. Set GOOGLE_GENAI_USE_VERTEXAI=true "
            "(recommended) or GEMINI_API_KEY."
        )
    return GeminiModel(client_args={"api_key": api_key}, model_id=model_id)


SYSTEM_PROMPT = """You are an expert DevOps engineer and cloud security analyst.
You have tools to analyze AWS and GCP infrastructure and to fetch web content.
Always:
- Ground recommendations in the structured tool findings; never invent facts.
- When a tool returns status="error", explain the cause to the user (e.g.
  missing credentials, insufficient IAM) and the remediation shown in the hint.
- Prefer Zero-Trust best practices: least privilege IAM, IAP-protected
  ingress, no public buckets, no default service accounts, no primitive roles.

Using the `fetch` tool (MCP):
- On the FIRST call, always pass `max_length=50000` so typical docs pages
  fit in one response. Never call it with the default 5000.
- If you still see `<error>Content truncated</error>`, call it ONCE more
  with `start_index` set to the previous content length and a large
  `max_length`. Do NOT chain more than 2 calls for the same URL; instead
  summarize with what you have and tell the user the page was long.
- Never re-fetch the same URL with the same arguments — that is a loop.
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevOps agent CLI")
    parser.add_argument(
        "--session-id",
        dest="session_id",
        default=None,
        help="Explicit session id (overrides --new-session and auto-resume).",
    )
    parser.add_argument(
        "--new-session",
        dest="new_session",
        action="store_true",
        help="Force a fresh semantic session id instead of resuming the last one.",
    )
    parser.add_argument(
        "--list-sessions",
        dest="list_sessions",
        action="store_true",
        help="List known sessions (most recently used first) and exit.",
    )
    return parser.parse_args()


async def main() -> None:
    args = _parse_args()

    state = load_state()

    if args.list_sessions:
        print(format_session_list(state))
        return

    session_id, is_new = resolve_session_id(
        cli_value=args.session_id,
        force_new=args.new_session,
        state=state,
    )
    register_session(state, session_id)

    configure_logging(session_id=session_id)
    configure_tracing()

    logger = logging.getLogger(__name__)
    logger.info(
        "%s session %s", "Created" if is_new else "Resumed", session_id
    )

    session_manager = get_session_manager(session_id)

    custom_tools = [
        analyze_aws_infra,
        check_s3_encryption,
        analyze_gcp_infra,
        scan_gcp_iam_roles,
        audit_gcp_service_account_keys,
        scan_gcs_buckets,
        scan_cloudrun_services,
        scan_gcp_network,
    ]

    mcp_client: MCPClient | None = None
    mcp_servers: list[str] = []
    try:
        logger.info("Connecting to MCP Server (mcp-server-fetch)")
        # Launch the server with a minimized env. Without this, shell init
        # hooks (nvm/pnpm/node auto-install, "added N packages" messages,
        # etc.) can leak to stdout and corrupt the JSON-RPC stream.
        clean_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "LANG": os.environ.get("LANG", "en_US.UTF-8"),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        mcp_server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_server_fetch"],
            env=clean_env,
        )
        mcp_client = MCPClient(transport_callable=lambda: stdio_client(mcp_server_params))
        custom_tools.append(mcp_client)
        mcp_servers.append("mcp-server-fetch")
    except Exception as exc:  # noqa: BLE001 - MCP is optional; keep CLI usable
        logger.warning("MCP fetch server unavailable (%s); continuing without it.", exc)

    model = _build_gemini_model()
    logger.info("LLM backend: %s", type(model).__name__)

    agent = Agent(
        model=model,
        tools=custom_tools,
        session_manager=session_manager,
        system_prompt=SYSTEM_PROMPT,
        # Silence Strands' default stdout callback — we own the UI via `ui.AgentUI`.
        # Without this, every token and tool call gets printed twice (once by the
        # default handler writing to stdout, once by our Live rich render).
        callback_handler=None,
    )

    ui = AgentUI()
    model_label = getattr(model, "config", {}).get("model_id", type(model).__name__)
    ui.show_banner(
        session_id=session_id,
        is_new=is_new,
        model_name=str(model_label),
        mcp_tools=mcp_servers if mcp_client else None,
    )

    try:
        while True:
            try:
                user_input = ui.prompt_user()
            except (EOFError, KeyboardInterrupt):
                break
            command = user_input.strip().lower()
            if command in {"exit", "quit"}:
                break
            if command in {"sessions", "/sessions"}:
                ui.print_sessions(format_session_list(load_state()))
                continue
            if command in {"mcp", "/mcp"}:
                if mcp_client is None:
                    ui.print_error("MCP client is not connected in this session.")
                else:
                    # Strands already manages the client lifecycle. Surface
                    # whether the agent has picked up any tools from it.
                    registered = [
                        spec.tool_name
                        for spec in agent.tool_registry.registry.values()
                    ]
                    fetch_tools = [t for t in registered if t.startswith("fetch")]
                    ui.print_sessions(
                        f"MCP servers configured: {', '.join(mcp_servers)}\n"
                        f"Tools registered in agent: {len(registered)} total\n"
                        f"MCP-originated tools (by convention): {', '.join(fetch_tools) or '(none visible yet — try asking the agent to fetch a URL)'}"
                    )
                continue
            if not user_input.strip():
                continue
            try:
                await ui.stream_turn(agent.stream_async(user_input))
                increment_turn(state, session_id)
            except Exception as exc:  # noqa: BLE001 - surface unexpected failures to the human
                logger.exception("Agent turn failed")
                ui.print_error(str(exc))
    finally:
        if mcp_client is not None and hasattr(mcp_client, "close"):
            try:
                mcp_client.close()
            except Exception:  # noqa: BLE001
                pass


if __name__ == "__main__":
    asyncio.run(main())
