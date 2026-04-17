"""GCP Cloud Run analysis tools.

Evaluates Cloud Run services against Zero-Trust architecture best practices:
services should sit behind IAP, not accept unauthenticated invokers, avoid
the default compute SA, and deploy to the configured primary region.
"""

from __future__ import annotations

import logging

from google.cloud import run_v2
from strands import tool

from tools._common import (
    ARTIFACT_REGISTRY_REGION,
    PRIMARY_REGION,
    Finding,
    as_tool_result,
    error_result,
    handle_gcp_exception,
    traced_tool,
)

logger = logging.getLogger(__name__)

_DEFAULT_COMPUTE_SA_SUFFIX = "-compute@developer.gserviceaccount.com"
_PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}
_IAP_ANNOTATION = "run.googleapis.com/iap-enabled"


def _inspect_service(
    service: run_v2.Service,
    services_client: run_v2.ServicesClient,
) -> list[Finding]:
    findings: list[Finding] = []
    resource = service.name
    service_short = service.name.split("/")[-1]
    region = service.name.split("/")[3] if "/locations/" in service.name else "unknown"

    try:
        policy = services_client.get_iam_policy(request={"resource": service.name})
        for binding in policy.bindings:
            public = set(binding.members) & _PUBLIC_PRINCIPALS
            if public and binding.role == "roles/run.invoker":
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        resource=resource,
                        category="cloudrun.unauthenticated_invoker",
                        message=(
                            f"Cloud Run service {service_short} allows {sorted(public)} "
                            "as invoker (public ingress)."
                        ),
                        recommendation=(
                            "Remove allUsers/allAuthenticatedUsers from roles/run.invoker "
                            "and front the service with IAP + Global Load Balancer."
                        ),
                        metadata={"members": sorted(public)},
                    )
                )
    except Exception as exc:
        logger.warning("Could not read IAM policy for %s: %s", service.name, exc)

    annotations = dict(service.annotations or {})
    iap_enabled = annotations.get(_IAP_ANNOTATION, "").lower() == "true"
    if not iap_enabled:
        findings.append(
            Finding(
                severity="HIGH",
                resource=resource,
                category="cloudrun.iap_not_enabled",
                message=(
                    f"Cloud Run service {service_short} does not have IAP enabled."
                ),
                recommendation=(
                    "Enable IAP on the service (gcloud run deploy --iap) and ensure "
                    "access is gated by Google Groups with FIDO2 2FA."
                ),
            )
        )

    template = service.template
    sa_email = template.service_account if template else ""
    if sa_email.endswith(_DEFAULT_COMPUTE_SA_SUFFIX) or not sa_email:
        findings.append(
            Finding(
                severity="HIGH",
                resource=resource,
                category="cloudrun.default_service_account",
                message=(
                    f"Cloud Run service {service_short} runs as the default compute "
                    "service account or has none set."
                ),
                recommendation=(
                    "Create a dedicated service account with only the roles required "
                    "by the workload and set it as the runtime identity."
                ),
                metadata={"service_account": sa_email},
            )
        )

    if region not in {PRIMARY_REGION, ARTIFACT_REGISTRY_REGION}:
        findings.append(
            Finding(
                severity="INFO",
                resource=resource,
                category="cloudrun.region_out_of_standard",
                message=(
                    f"Cloud Run service {service_short} is deployed in {region}."
                ),
                recommendation=(
                    f"Configured primary region is {PRIMARY_REGION}; confirm this "
                    "deployment is intentional (e.g. DR secondary)."
                ),
                metadata={"region": region},
            )
        )

    return findings


@tool
@traced_tool("scan_cloudrun_services")
def scan_cloudrun_services(project_id: str, location: str = "-") -> str:
    """Scan Cloud Run services for Zero-Trust architecture compliance.

    Args:
        project_id: GCP project id.
        location: Cloud Run region, or "-" to scan every region.

    Returns:
        JSON string with {status, findings_count, findings[]}.
    """
    if not project_id:
        return error_result("project_id is required")

    try:
        client = run_v2.ServicesClient()
        parent = f"projects/{project_id}/locations/{location}"
        findings: list[Finding] = []
        count = 0
        for service in client.list_services(request={"parent": parent}):
            count += 1
            findings.extend(_inspect_service(service, client))
        return as_tool_result(
            findings,
            summary=f"Inspected {count} Cloud Run services in {project_id}/{location}.",
        )
    except Exception as exc:
        return handle_gcp_exception(
            exc, operation=f"Cloud Run scan for {project_id}"
        )
