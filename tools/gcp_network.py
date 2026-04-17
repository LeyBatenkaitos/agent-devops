"""GCP VPC and firewall analysis tools.

Detects open ingress rules (`0.0.0.0/0`), use of the legacy `default` VPC,
firewall rules without Cloud Logging, and overly-broad protocol/port specs.
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

_INSECURE_OPEN_CIDR = "0.0.0.0/0"


def _inspect_firewall(
    rule: compute_v1.Firewall, project_id: str
) -> list[Finding]:
    findings: list[Finding] = []
    resource = f"projects/{project_id}/global/firewalls/{rule.name}"

    if rule.direction == "INGRESS" and _INSECURE_OPEN_CIDR in (rule.source_ranges or []):
        allows_all_ports = any(
            not allowed.ports for allowed in rule.allowed
        )
        allows_all_protocols = any(
            allowed.I_p_protocol in {"all", "0"} for allowed in rule.allowed
        )
        severity = "CRITICAL" if (allows_all_ports or allows_all_protocols) else "HIGH"
        findings.append(
            Finding(
                severity=severity,  # type: ignore[arg-type]
                resource=resource,
                category="network.firewall_open_to_world",
                message=(
                    f"Firewall rule {rule.name} allows ingress from 0.0.0.0/0."
                ),
                recommendation=(
                    "Restrict source_ranges to known corporate CIDRs, IAP TCP "
                    "forwarding ranges (35.235.240.0/20), or Google health check ranges."
                ),
                metadata={
                    "allowed": [
                        {"protocol": a.I_p_protocol, "ports": list(a.ports)}
                        for a in rule.allowed
                    ],
                },
            )
        )

    log_config = getattr(rule, "log_config", None)
    if log_config is not None and not log_config.enable:
        findings.append(
            Finding(
                severity="LOW",
                resource=resource,
                category="network.firewall_logging_disabled",
                message=f"Firewall rule {rule.name} has Cloud Logging disabled.",
                recommendation="Enable firewall rule logging on sensitive ingress/egress rules for auditing.",
            )
        )

    return findings


@tool
@traced_tool("scan_gcp_network")
def scan_gcp_network(project_id: str) -> str:
    """Scan VPCs and firewall rules for network security compliance.

    Args:
        project_id: GCP project id.

    Returns:
        JSON string with {status, findings_count, findings[]}.
    """
    if not project_id:
        return error_result("project_id is required")

    try:
        networks_client = compute_v1.NetworksClient()
        firewall_client = compute_v1.FirewallsClient()

        findings: list[Finding] = []
        networks = list(networks_client.list(project=project_id))
        for net in networks:
            if net.name == "default":
                findings.append(
                    Finding(
                        severity="HIGH",
                        resource=f"projects/{project_id}/global/networks/default",
                        category="network.default_vpc_in_use",
                        message="Project still uses the legacy 'default' VPC.",
                        recommendation=(
                            "Delete the default VPC and provision a custom VPC with "
                            "explicit subnets per a proper landing zone design."
                        ),
                    )
                )

        firewall_count = 0
        for rule in firewall_client.list(project=project_id):
            firewall_count += 1
            findings.extend(_inspect_firewall(rule, project_id))

        return as_tool_result(
            findings,
            summary=(
                f"Scanned {len(networks)} VPCs and {firewall_count} firewall rules "
                f"in {project_id}."
            ),
        )
    except Exception as exc:
        return handle_gcp_exception(
            exc, operation=f"network scan for {project_id}"
        )
