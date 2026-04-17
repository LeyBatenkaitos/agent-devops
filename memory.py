"""Session storage for the DevOps agent.

Thin wrapper around Strands' ``FileSessionManager``. The storage directory
lives under ``$XDG_CONFIG_HOME/agent-devops/sessions`` (see ``sessions.py``)
so conversation state survives across checkouts and is independent of the
current working directory.
"""

from __future__ import annotations

import logging

from strands.session import FileSessionManager, SessionManager

from sessions import sessions_dir

logger = logging.getLogger(__name__)


def get_session_manager(session_id: str) -> SessionManager:
    """Return a file-backed session manager for the given session id."""

    directory = str(sessions_dir())
    logger.debug("Using FileSessionManager at %s for session %s", directory, session_id)
    return FileSessionManager(session_id=session_id, directory=directory)
