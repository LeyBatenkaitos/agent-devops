"""Optional OpenTelemetry tracer bootstrap with Google Cloud Trace exporter.

Off by default. Activated only when `OTEL_ENABLED=true`. Requires the
`opentelemetry-sdk` and `opentelemetry-exporter-gcp-trace` packages and an
ADC-authenticated GCP project.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def configure_tracing(service_name: str = "agent-devops") -> bool:
    """Install a Cloud Trace exporter on the global tracer provider.

    Returns:
        True if tracing was configured, False if it is disabled or the
        dependencies are not installed.
    """

    if os.environ.get("OTEL_ENABLED", "false").lower() != "true":
        logger.debug("Tracing disabled (OTEL_ENABLED != 'true').")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        logger.warning(
            "OTEL_ENABLED=true but OpenTelemetry packages missing: %s. "
            "Install opentelemetry-sdk and opentelemetry-exporter-gcp-trace.",
            exc,
        )
        return False

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
    trace.set_tracer_provider(provider)
    logger.info("OpenTelemetry + Cloud Trace exporter active for %s.", service_name)
    return True
