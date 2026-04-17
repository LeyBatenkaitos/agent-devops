"""Shared utilities for GCP analysis tools.

Provides a common `Finding` schema, a JSON serializer for @tool results, a
credential-aware exception helper, and an optional OpenTelemetry span decorator
(`traced_tool`) that activates when `OTEL_ENABLED=true`.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Literal, TypeVar

from google.api_core import exceptions as gapi_exceptions
from google.auth import exceptions as gauth_exceptions

logger = logging.getLogger(__name__)

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

PRIMARY_REGION = "us-east1"
ARTIFACT_REGISTRY_REGION = "southamerica-west1"


@dataclass
class Finding:
    """Canonical finding emitted by every GCP analysis tool.

    Kept flat so the LLM can summarize it without deep traversal.
    """

    severity: Severity
    resource: str
    category: str
    message: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)


def as_tool_result(
    findings: Iterable[Finding],
    *,
    status: Literal["success", "error", "partial"] = "success",
    summary: str | None = None,
) -> str:
    """Serialize a list of findings into the canonical JSON string Strands tools return."""

    findings_list = [asdict(f) for f in findings]
    payload: dict[str, Any] = {
        "status": status,
        "findings_count": len(findings_list),
        "findings": findings_list,
    }
    if summary:
        payload["summary"] = summary
    return json.dumps(payload, default=str)


def error_result(message: str, *, hint: str | None = None) -> str:
    """Serialize an error condition in the same envelope the LLM expects."""

    payload: dict[str, Any] = {"status": "error", "message": message}
    if hint:
        payload["hint"] = hint
    return json.dumps(payload)


_API_NAME_RE = re.compile(r"([a-z0-9-]+\.googleapis\.com)")


def _extract_api_name(message: str) -> str:
    """Pull the `*.googleapis.com` endpoint out of a GCP error message.

    Falls back to the literal ``<api>`` placeholder when the message does not
    contain a recognizable API hostname.
    """

    match = _API_NAME_RE.search(message)
    return match.group(1) if match else "<api>"


def handle_gcp_exception(exc: Exception, *, operation: str) -> str:
    """Map a GCP SDK exception to an actionable tool-result string.

    The goal is that the LLM (and the human) can tell apart "your credentials
    are missing" from "you lack IAM permission on this project" without reading
    a Python traceback.
    """

    if isinstance(exc, gauth_exceptions.DefaultCredentialsError):
        return error_result(
            f"{operation} failed: no Application Default Credentials found.",
            hint="Run `gcloud auth application-default login` for local use, "
            "or attach a service account to the runtime environment.",
        )
    if isinstance(exc, gapi_exceptions.PermissionDenied):
        # Google returns PermissionDenied for two very different conditions:
        #   (a) the caller truly lacks an IAM role, and
        #   (b) the target API is not enabled on the project.
        # The SDK exception message disambiguates them — surface the right hint.
        message = str(getattr(exc, "message", "") or exc)
        api_disabled_signals = (
            "has not been used",
            "it is disabled",
            "SERVICE_DISABLED",
            "API is not enabled",
        )
        if any(signal in message for signal in api_disabled_signals):
            api_hint = _extract_api_name(message)
            return error_result(
                f"{operation} failed: required Google API is not enabled on the project.",
                hint=(
                    f"Enable the API with `gcloud services enable {api_hint}` "
                    "(or via the Cloud Console) and retry. Owner/viewer roles "
                    "don't help when the API itself is off."
                ),
            )
        return error_result(
            f"{operation} failed: caller lacks required IAM permissions.",
            hint="Grant the calling identity the minimum viewer/inspector role "
            "(e.g. roles/iam.securityReviewer, roles/viewer) on the target project.",
        )
    if isinstance(exc, gapi_exceptions.NotFound):
        return error_result(
            f"{operation} failed: resource not found.",
            hint="Verify the project id / location arguments are correct and "
            "that the resource exists in the target project.",
        )
    if isinstance(exc, gapi_exceptions.GoogleAPICallError):
        return error_result(
            f"{operation} failed with GCP API error: {exc.message}",
            hint="Check Cloud Logging for the corresponding API error and "
            "confirm the target API is enabled on the project.",
        )
    logger.exception("Unexpected failure during %s", operation)
    return error_result(f"{operation} failed unexpectedly: {exc!s}")


F = TypeVar("F", bound=Callable[..., Any])


def traced_tool(name: str) -> Callable[[F], F]:
    """Wrap a @tool function with an OpenTelemetry span when OTEL_ENABLED=true.

    When observability is disabled (default), returns the function unchanged so
    there is zero runtime cost. The import of opentelemetry is lazy so the base
    install does not require the OTel packages.
    """

    def decorator(func: F) -> F:
        if os.environ.get("OTEL_ENABLED", "false").lower() != "true":
            return func

        try:
            from opentelemetry import trace

            tracer = trace.get_tracer("agent-devops.tools")
        except ImportError:
            logger.warning(
                "OTEL_ENABLED=true but opentelemetry is not installed; tracing disabled."
            )
            return func

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with tracer.start_as_current_span(f"tool.{name}") as span:
                span.set_attribute("tool.name", name)
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("tool.status", "ok")
                    return result
                except Exception as exc:
                    span.set_attribute("tool.status", "error")
                    span.record_exception(exc)
                    raise

        return wrapper  # type: ignore[return-value]

    return decorator
