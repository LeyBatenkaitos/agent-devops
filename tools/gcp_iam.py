"""GCP IAM analysis tools.

Replaces the former hardcoded placeholder in tools/gcp.py. Actually queries
the Resource Manager and IAM APIs and emits structured findings aligned with
the Zero-Trust principle of least privilege.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from google.cloud import resourcemanager_v3
from google.cloud import iam_admin_v1
from strands import tool

from tools._common import (
    Finding,
    as_tool_result,
    error_result,
    handle_gcp_exception,
    traced_tool,
)

logger = logging.getLogger(__name__)

_PRIMITIVE_ROLES = {
    "roles/owner": "CRITICAL",
    "roles/editor": "HIGH",
    "roles/viewer": "MEDIUM",
}

_SA_KEY_MAX_AGE_DAYS = 90


@tool
@traced_tool("scan_gcp_iam_roles")
def scan_gcp_iam_roles(project_id: str) -> str:
    """Scan IAM bindings on a GCP project for overly permissive roles.

    Flags primitive roles (owner/editor/viewer) per least-privilege
    best practices and highlights user-type members bound to high-privilege roles.

    Args:
        project_id: The GCP project id to scan (not the numeric id).

    Returns:
        JSON string with {status, findings_count, findings[]}.
    """
    if not project_id:
        return error_result("project_id is required")

    try:
        client = resourcemanager_v3.ProjectsClient()
        policy = client.get_iam_policy(resource=f"projects/{project_id}")
    except Exception as exc:
        return handle_gcp_exception(exc, operation=f"IAM policy fetch for {project_id}")

    findings: list[Finding] = []
    for binding in policy.bindings:
        role = binding.role
        if role in _PRIMITIVE_ROLES:
            severity = _PRIMITIVE_ROLES[role]
            for member in binding.members:
                member_kind = member.split(":", 1)[0]
                finding_severity = severity
                if member_kind == "user" and severity in {"HIGH", "CRITICAL"}:
                    finding_severity = "CRITICAL"
                findings.append(
                    Finding(
                        severity=finding_severity,  # type: ignore[arg-type]
                        resource=f"projects/{project_id}",
                        category="iam.primitive_role",
                        message=f"Member {member} is granted primitive role {role}.",
                        recommendation=(
                            "Replace primitive roles with predefined or custom roles "
                            "granting only the specific permissions needed."
                        ),
                        metadata={"role": role, "member": member},
                    )
                )

    return as_tool_result(
        findings,
        summary=f"Scanned {len(policy.bindings)} IAM bindings on {project_id}.",
    )


@tool
@traced_tool("audit_gcp_service_account_keys")
def audit_gcp_service_account_keys(project_id: str, max_age_days: int = _SA_KEY_MAX_AGE_DAYS) -> str:
    """Audit user-managed service account keys for age and existence.

    Security best practice is to prefer Workload Identity / ADC over JSON keys.
    Any user-managed key at all is a finding; keys older than `max_age_days`
    are escalated in severity.

    Args:
        project_id: The GCP project id that owns the service accounts.
        max_age_days: Threshold in days above which a key is considered stale.

    Returns:
        JSON string with {status, findings_count, findings[]}.
    """
    if not project_id:
        return error_result("project_id is required")

    try:
        iam_client = iam_admin_v1.IAMClient()
        sa_list_response = iam_client.list_service_accounts(
            request={"name": f"projects/{project_id}"}
        )
    except Exception as exc:
        return handle_gcp_exception(
            exc, operation=f"service account list for {project_id}"
        )

    findings: list[Finding] = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    for account in sa_list_response.accounts:
        try:
            keys_response = iam_client.list_service_account_keys(
                request={
                    "name": account.name,
                    "key_types": [
                        iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED
                    ],
                }
            )
        except Exception as exc:
            logger.warning(
                "Could not list keys for %s: %s", account.email, exc
            )
            continue

        for key in keys_response.keys:
            valid_after = getattr(key, "valid_after_time", None)
            key_age_days: int | None = None
            if valid_after:
                key_age_days = (datetime.now(timezone.utc) - valid_after).days

            is_stale = valid_after is not None and valid_after < cutoff
            severity = "HIGH" if is_stale else "MEDIUM"
            msg = (
                f"Service account {account.email} has a user-managed key"
                + (f" ({key_age_days} days old)." if key_age_days is not None else ".")
            )
            findings.append(
                Finding(
                    severity=severity,  # type: ignore[arg-type]
                    resource=account.email,
                    category="iam.user_managed_key",
                    message=msg,
                    recommendation=(
                        "Replace user-managed keys with Workload Identity or ADC. "
                        "If a key is required, rotate it at most every 90 days."
                    ),
                    metadata={
                        "key_name": key.name,
                        "age_days": key_age_days,
                        "stale": is_stale,
                    },
                )
            )

    return as_tool_result(
        findings,
        summary=f"Audited keys for {len(sa_list_response.accounts)} service accounts.",
    )
