"""Dual-format logging: human-friendly in a TTY, JSON everywhere else.

Call ``configure_logging()`` once at program start. All subsequent
``logging.getLogger(...)`` calls inherit the active formatter.

Format selection (in order of precedence):

1. ``LOG_FORMAT=json``  → always structured JSON (Cloud Logging shape).
2. ``LOG_FORMAT=pretty`` → always colored human format.
3. ``LOG_FORMAT=auto`` (default) → JSON when stderr is not a TTY (piped,
   redirected, running under Cloud Run / GKE) and pretty when it is a TTY.

The JSON shape is unchanged from the previous implementation so Cloud
Logging ingestion keeps working when deployed.

Environment variables:
    LOG_LEVEL:  DEBUG | INFO | WARNING | ERROR | CRITICAL  (default: INFO)
    LOG_FORMAT: auto | pretty | json                       (default: auto)
    NO_COLOR:   if set (any value) disables ANSI colors in pretty mode
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

_SEVERITY_MAP = {
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "WARNING": "WARNING",
    "ERROR": "ERROR",
    "CRITICAL": "CRITICAL",
}

# ANSI SGR codes. Kept local so we don't pull a color library dependency.
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_LEVEL_COLORS = {
    "DEBUG": "\033[36m",     # cyan
    "INFO": "\033[32m",      # green
    "WARNING": "\033[33m",   # yellow
    "ERROR": "\033[31m",     # red
    "CRITICAL": "\033[1;41m",  # bold on red background
}

# Logger name prefixes that are too chatty at INFO from third-party libs;
# bumped to WARNING automatically so the human CLI stays readable. Users can
# still force DEBUG globally via LOG_LEVEL=DEBUG.
_NOISY_LOGGERS = (
    "google",
    "google.auth",
    "google_genai",
    "google.genai",
    "httpx",
    "httpcore",
    "urllib3",
    "asyncio",
    "strands.telemetry",
)


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log line, matching Cloud Logging's ``jsonPayload`` shape."""

    def __init__(self, *, session_id: str | None = None) -> None:
        super().__init__()
        self._session_id = session_id

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "severity": _SEVERITY_MAP.get(record.levelname, record.levelname),
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
        }
        if self._session_id:
            payload["session_id"] = self._session_id
        session_from_record = getattr(record, "session_id", None)
        if session_from_record:
            payload["session_id"] = session_from_record
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class PrettyFormatter(logging.Formatter):
    """Human-readable one-line format for local TTY use.

    Example output:

        12:04:07  INFO  main            Created session gabriel-proj-20260417
    """

    def __init__(self, *, use_color: bool) -> None:
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        level = record.levelname
        if self._use_color:
            level_display = f"{_LEVEL_COLORS.get(level, '')}{level:<7}{_RESET}"
            logger_display = f"{_DIM}{record.name:<16}{_RESET}"
        else:
            level_display = f"{level:<7}"
            logger_display = f"{record.name:<16}"
        message = record.getMessage()
        line = f"{ts}  {level_display} {logger_display} {message}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def _select_format(stream) -> str:
    """Decide 'json' vs 'pretty' based on LOG_FORMAT and TTY detection."""

    override = os.environ.get("LOG_FORMAT", "auto").lower()
    if override in {"json", "pretty"}:
        return override
    try:
        is_tty = stream.isatty()
    except (AttributeError, ValueError):
        is_tty = False
    return "pretty" if is_tty else "json"


def _should_use_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def configure_logging(session_id: str | None = None) -> None:
    """Install the appropriate formatter on the root logger. Idempotent."""

    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    stream = sys.stderr
    fmt = _select_format(stream)

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=stream)
    if fmt == "pretty":
        handler.setFormatter(PrettyFormatter(use_color=_should_use_color(stream)))
    else:
        handler.setFormatter(JsonFormatter(session_id=session_id))
    root.addHandler(handler)
    root.setLevel(level)

    # Quiet third-party libraries in pretty mode so the CLI doesn't drown the
    # user in SDK chatter. JSON mode keeps everything for Cloud Logging.
    if fmt == "pretty" and level > logging.DEBUG:
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(max(level, logging.WARNING))
