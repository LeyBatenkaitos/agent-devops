"""Session identity and registry for the DevOps agent.

Provides:

* Semantic session ids derived from the active GCP user + project + date
  (e.g. ``alice-my-project-20260417``) with a uuid fallback when gcloud is
  not available.
* A tiny JSON registry under ``$XDG_CONFIG_HOME/agent-devops/state.json``
  that tracks the last-used session and a per-session ``turn_count`` so the
  agent can auto-resume and list prior sessions.
* Helpers used by ``main.py`` to implement ``--list-sessions`` and
  ``--new-session`` flags without bloating the entry point.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_STATE_FILENAME = "state.json"
_SESSIONS_SUBDIR = "sessions"
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _config_home() -> Path:
    """Resolve the agent config directory (XDG-compliant)."""

    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "agent-devops"


def sessions_dir() -> Path:
    """Directory where FileSessionManager persists conversation state."""

    path = _config_home() / _SESSIONS_SUBDIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def state_file() -> Path:
    """JSON registry path tracking last session + per-session metadata."""

    path = _config_home() / _STATE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class SessionMeta:
    id: str
    created_at: str
    last_used_at: str
    turn_count: int = 0
    gcp_user: str | None = None
    gcp_project: str | None = None


@dataclass
class RegistryState:
    last_session_id: str | None = None
    sessions: dict[str, SessionMeta] = field(default_factory=dict)


def _slug(value: str) -> str:
    """Normalize an arbitrary string into a filesystem-safe lowercase slug."""

    return _SLUG_RE.sub("-", value.lower()).strip("-")


def _gcloud_value(key: str) -> str | None:
    """Best-effort read of a single ``gcloud config`` value.

    Returns ``None`` when gcloud is absent, unauthenticated, or the key is
    unset. Never raises — the caller falls back to uuid-only ids.
    """

    try:
        result = subprocess.run(
            ["gcloud", "config", "get-value", key],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.debug("gcloud lookup for %s skipped: %s", key, exc)
        return None
    value = result.stdout.strip()
    if not value or value.lower() in {"(unset)", "none"}:
        return None
    return value


def _semantic_base_id() -> tuple[str, str | None, str | None]:
    """Return ``(base_id, gcp_user, gcp_project)`` without any suffix.

    ``base_id`` is the human-meaningful prefix (e.g. ``alice-my-project``).
    If no gcloud context is available, falls back to a short uuid slug.
    """

    account = _gcloud_value("account")
    project = _gcloud_value("core/project")
    date = datetime.now(timezone.utc).strftime("%Y%m%d")

    user_part: str | None = None
    if account:
        user_part = _slug(account.split("@", 1)[0])

    project_part: str | None = None
    if project:
        project_part = _slug(project)

    if not user_part and not project_part:
        return f"devops-{uuid.uuid4().hex[:8]}", None, None

    parts = [p for p in (user_part, project_part, date) if p]
    return "-".join(parts), account, project


def load_state() -> RegistryState:
    """Load the registry, returning an empty ``RegistryState`` when missing."""

    path = state_file()
    if not path.exists():
        return RegistryState()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("State file %s unreadable (%s); starting fresh", path, exc)
        return RegistryState()

    sessions = {
        sid: SessionMeta(**meta)
        for sid, meta in raw.get("sessions", {}).items()
        if isinstance(meta, dict)
    }
    return RegistryState(
        last_session_id=raw.get("last_session_id"),
        sessions=sessions,
    )


def save_state(state: RegistryState) -> None:
    """Atomically persist the registry to disk."""

    path = state_file()
    tmp = path.with_suffix(".json.tmp")
    payload = {
        "last_session_id": state.last_session_id,
        "sessions": {sid: asdict(meta) for sid, meta in state.sessions.items()},
    }
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _unique_suffix(base: str, existing: set[str]) -> str:
    """Return ``base``, or ``base-2``, ``base-3``… so the id does not collide."""

    if base not in existing:
        return base
    for n in range(2, 1000):
        candidate = f"{base}-{n}"
        if candidate not in existing:
            return candidate
    return f"{base}-{uuid.uuid4().hex[:6]}"


def resolve_session_id(
    *,
    cli_value: str | None,
    force_new: bool,
    state: RegistryState,
) -> tuple[str, bool]:
    """Determine which session id the current run should use.

    Resolution order:
    1. ``--session-id`` CLI value (always wins).
    2. ``DEVOPS_SESSION_ID`` env var.
    3. If ``--new-session`` was passed, build a fresh semantic id with a
       deduped numeric suffix.
    4. Otherwise, reuse the registry's ``last_session_id`` when present.
    5. Fall back to a fresh semantic id.

    Returns ``(session_id, is_new)`` where ``is_new`` flags whether the
    caller is creating a new session (vs. resuming an existing one).
    """

    if cli_value:
        return cli_value, cli_value not in state.sessions

    env_value = os.environ.get("DEVOPS_SESSION_ID")
    if env_value:
        return env_value, env_value not in state.sessions

    base, _, _ = _semantic_base_id()

    if force_new:
        return _unique_suffix(base, set(state.sessions)), True

    if state.last_session_id and state.last_session_id in state.sessions:
        return state.last_session_id, False

    return _unique_suffix(base, set(state.sessions)), True


def register_session(state: RegistryState, session_id: str) -> SessionMeta:
    """Create or refresh a session entry and mark it as the last used."""

    now = datetime.now(timezone.utc).isoformat()
    meta = state.sessions.get(session_id)
    _, account, project = _semantic_base_id()
    if meta is None:
        meta = SessionMeta(
            id=session_id,
            created_at=now,
            last_used_at=now,
            turn_count=0,
            gcp_user=account,
            gcp_project=project,
        )
    else:
        meta.last_used_at = now
        if account and not meta.gcp_user:
            meta.gcp_user = account
        if project and not meta.gcp_project:
            meta.gcp_project = project
    state.sessions[session_id] = meta
    state.last_session_id = session_id
    save_state(state)
    return meta


def increment_turn(state: RegistryState, session_id: str) -> None:
    """Bump the turn counter after a successful agent response."""

    meta = state.sessions.get(session_id)
    if meta is None:
        return
    meta.turn_count += 1
    meta.last_used_at = datetime.now(timezone.utc).isoformat()
    save_state(state)


def _format_relative(iso_ts: str) -> str:
    """Render a timestamp as ``today``, ``yesterday``, ``Nd ago``."""

    try:
        ts = datetime.fromisoformat(iso_ts)
    except ValueError:
        return iso_ts
    delta = datetime.now(timezone.utc) - ts
    days = delta.days
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    return f"{days}d ago"


def format_session_list(state: RegistryState) -> str:
    """Return a human-readable listing for ``--list-sessions``."""

    if not state.sessions:
        return "(no sessions yet)"
    rows = sorted(
        state.sessions.values(),
        key=lambda m: m.last_used_at,
        reverse=True,
    )
    lines = []
    for meta in rows:
        marker = "*" if meta.id == state.last_session_id else " "
        lines.append(
            f"{marker} {meta.id}  "
            f"(last used: {_format_relative(meta.last_used_at)}, "
            f"{meta.turn_count} turns)"
        )
    return "\n".join(lines)
