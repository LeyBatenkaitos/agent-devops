"""GCP Compute Engine analysis tools.

Replaces the shallow default-SA-only check in tools/gcp.py with a broader
set of security checks covering GCP Zero-Trust best practices:
public IPs, OS Login, Shielded VM, IP forwarding, project-wide SSH keys,
and default compute service account usage.
"""

from __future__ import annotations

import logging

from google.cloud import compute_v1
from strands import tool

from tools._common import (
    Finding,
    as_tool_result,
    error_result,
    handle_gcp_exception,
    traced_tool,
)

logger = logging.getLogger(__name__)

_DEFAULT_COMPUTE_SA_SUFFIX = "-compute@developer.gserviceaccount.com"


def _metadata_items_as_dict(metadata: compute_v1.Metadata | None) -> dict[str, str]:
    if metadata is None or not metadata.items:
        return {}
    return {item.key: item.value for item in metadata.items}


def _inspect_instance(
    instance: compute_v1.Instance, project_id: str, zone: str
) -> list[Finding]:
    findings: list[Finding] = []
    resource = f"projects/{project_id}/zones/{zone}/instances/{instance.name}"

    for nic in instance.network_interfaces:
        for access_config in nic.access_configs:
            if access_config.nat_i_p or access_config.type_ == "ONE_TO_ONE_NAT":
                findings.append(
                    Finding(
                        severity="HIGH",
                        resource=resource,
                        category="compute.public_ip",
                        message=f"Instance {instance.name} has an external (public) IP.",
                        recommendation=(
                            "Remove the external IP and route traffic via Cloud NAT, "
                            "IAP TCP forwarding, or a private Load Balancer."
                        ),
                        metadata={"nic": nic.name, "nat_ip": access_config.nat_i_p},
                    )
                )

    for sa in instance.service_accounts:
        if sa.email.endswith(_DEFAULT_COMPUTE_SA_SUFFIX):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    resource=resource,
                    category="compute.default_service_account",
                    message=(
                        f"Instance {instance.name} uses the default compute "
                        f"service account ({sa.email})."
                    ),
                    recommendation=(
                        "Create a dedicated service account with only the IAM "
                        "roles the workload needs and attach it to the instance."
                    ),
                    metadata={"service_account": sa.email},
                )
            )

    metadata = _metadata_items_as_dict(instance.metadata)
    if metadata.get("enable-oslogin", "").upper() != "TRUE":
        findings.append(
            Finding(
                severity="MEDIUM",
                resource=resource,
                category="compute.os_login_disabled",
                message=f"Instance {instance.name} does not have OS Login enabled.",
                recommendation=(
                    "Set the instance metadata `enable-oslogin=TRUE` to enforce "
                    "centralized IAM-based SSH access."
                ),
            )
        )
    if metadata.get("block-project-ssh-keys", "").upper() != "TRUE":
        findings.append(
            Finding(
                severity="LOW",
                resource=resource,
                category="compute.project_ssh_keys_allowed",
                message=(
                    f"Instance {instance.name} inherits project-wide SSH keys."
                ),
                recommendation=(
                    "Set `block-project-ssh-keys=TRUE` on the instance metadata "
                    "to prevent project-level SSH keys from granting access."
                ),
            )
        )

    shielded = instance.shielded_instance_config
    if shielded and (
        not shielded.enable_secure_boot
        or not shielded.enable_vtpm
        or not shielded.enable_integrity_monitoring
    ):
        findings.append(
            Finding(
                severity="MEDIUM",
                resource=resource,
                category="compute.shielded_vm_disabled",
                message=(
                    f"Instance {instance.name} has Shielded VM features disabled."
                ),
                recommendation=(
                    "Enable Secure Boot, vTPM, and Integrity Monitoring on the "
                    "instance to defend against boot-level and kernel-level threats."
                ),
                metadata={
                    "secure_boot": shielded.enable_secure_boot,
                    "vtpm": shielded.enable_vtpm,
                    "integrity_monitoring": shielded.enable_integrity_monitoring,
                },
            )
        )

    if instance.can_ip_forward:
        findings.append(
            Finding(
                severity="MEDIUM",
                resource=resource,
                category="compute.ip_forwarding_enabled",
                message=(
                    f"Instance {instance.name} has IP forwarding enabled."
                ),
                recommendation=(
                    "Disable `canIpForward` unless the workload is a purpose-built "
                    "router or NAT appliance."
                ),
            )
        )

    return findings


@tool
@traced_tool("analyze_gcp_infra")
def analyze_gcp_infra(project_id: str, zone: str | None = None) -> str:
    """Analyze Compute Engine instances for GCP security best practices.

    When `zone` is omitted, scans every zone in the project via aggregated list.

    Args:
        project_id: GCP project id.
        zone: Optional single zone (e.g. "us-east1-b"). If omitted, scans all zones.

    Returns:
        JSON string with {status, findings_count, findings[]}.
    """
    if not project_id:
        return error_result("project_id is required")

    try:
        client = compute_v1.InstancesClient()
        findings: list[Finding] = []
        scanned = 0

        if zone:
            request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)
            for instance in client.list(request=request):
                scanned += 1
                findings.extend(_inspect_instance(instance, project_id, zone))
        else:
            agg_request = compute_v1.AggregatedListInstancesRequest(project=project_id)
            for zone_key, scoped_list in client.aggregated_list(request=agg_request):
                if not scoped_list.instances:
                    continue
                current_zone = zone_key.split("/")[-1]
                for instance in scoped_list.instances:
                    scanned += 1
                    findings.extend(
                        _inspect_instance(instance, project_id, current_zone)
                    )

        return as_tool_result(
            findings,
            summary=f"Inspected {scanned} Compute Engine instances in {project_id}.",
        )
    except Exception as exc:
        return handle_gcp_exception(
            exc, operation=f"Compute Engine scan for {project_id}"
        )
