"""GCP Cloud Storage analysis tools.

Detects buckets that violate data-protection best practices: public
access, missing uniform bucket-level access (UBLA), weak public-access
prevention, missing CMEK, and missing versioning or access logging.
"""

from __future__ import annotations

import logging

from google.cloud import storage
from strands import tool

from tools._common import (
    Finding,
    as_tool_result,
    error_result,
    handle_gcp_exception,
    traced_tool,
)

logger = logging.getLogger(__name__)

_PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}


def _inspect_bucket(bucket: storage.Bucket) -> list[Finding]:
    findings: list[Finding] = []
    resource = f"gs://{bucket.name}"

    iam_cfg = bucket.iam_configuration or {}
    ubla = getattr(iam_cfg, "uniform_bucket_level_access_enabled", None)
    if ubla is None:
        ubla = iam_cfg.get("uniformBucketLevelAccess", {}).get("enabled") if isinstance(iam_cfg, dict) else False
    if not ubla:
        findings.append(
            Finding(
                severity="HIGH",
                resource=resource,
                category="storage.ubla_disabled",
                message=f"Bucket {bucket.name} does not have Uniform Bucket-Level Access enabled.",
                recommendation="Enable UBLA to disable fine-grained ACLs and rely solely on IAM.",
            )
        )

    pap = getattr(iam_cfg, "public_access_prevention", None)
    if pap is None and isinstance(iam_cfg, dict):
        pap = iam_cfg.get("publicAccessPrevention")
    if pap != "enforced":
        findings.append(
            Finding(
                severity="HIGH",
                resource=resource,
                category="storage.public_access_prevention_not_enforced",
                message=(
                    f"Bucket {bucket.name} has public_access_prevention='{pap}'."
                ),
                recommendation="Set publicAccessPrevention to 'enforced' to block all public exposure.",
            )
        )

    try:
        policy = bucket.get_iam_policy(requested_policy_version=3)
        for binding in policy.bindings:
            members = set(binding.get("members", []))
            public = members & _PUBLIC_PRINCIPALS
            if public:
                findings.append(
                    Finding(
                        severity="CRITICAL",
                        resource=resource,
                        category="storage.public_binding",
                        message=(
                            f"Bucket {bucket.name} grants {binding['role']} to {sorted(public)}."
                        ),
                        recommendation="Remove allUsers/allAuthenticatedUsers bindings; grant access via Google Groups only.",
                        metadata={"role": binding["role"], "members": sorted(public)},
                    )
                )
    except Exception as exc:
        logger.warning("Could not read IAM policy for %s: %s", bucket.name, exc)

    if not getattr(bucket, "default_kms_key_name", None):
        findings.append(
            Finding(
                severity="LOW",
                resource=resource,
                category="storage.no_cmek",
                message=f"Bucket {bucket.name} has no customer-managed encryption key (CMEK).",
                recommendation="Attach a Cloud KMS key for workloads handling regulated or sensitive data.",
            )
        )

    if not getattr(bucket, "versioning_enabled", False):
        findings.append(
            Finding(
                severity="LOW",
                resource=resource,
                category="storage.versioning_disabled",
                message=f"Bucket {bucket.name} does not have versioning enabled.",
                recommendation="Enable object versioning to protect against accidental deletion or overwrite.",
            )
        )

    logging_cfg = getattr(bucket, "logging", None)
    if not logging_cfg or not getattr(logging_cfg, "get", lambda _k: None)("logBucket"):
        if not (isinstance(logging_cfg, dict) and logging_cfg.get("logBucket")):
            findings.append(
                Finding(
                    severity="LOW",
                    resource=resource,
                    category="storage.access_logging_disabled",
                    message=f"Bucket {bucket.name} has no access logging configured.",
                    recommendation="Route access logs to a central audit bucket for compliance and forensics.",
                )
            )

    return findings


@tool
@traced_tool("scan_gcs_buckets")
def scan_gcs_buckets(project_id: str) -> str:
    """Scan Cloud Storage buckets for public access and configuration gaps.

    Args:
        project_id: GCP project id owning the buckets.

    Returns:
        JSON string with {status, findings_count, findings[]}.
    """
    if not project_id:
        return error_result("project_id is required")

    try:
        client = storage.Client(project=project_id)
        findings: list[Finding] = []
        count = 0
        for bucket in client.list_buckets():
            count += 1
            bucket.reload()
            findings.extend(_inspect_bucket(bucket))
        return as_tool_result(
            findings, summary=f"Inspected {count} GCS buckets in {project_id}."
        )
    except Exception as exc:
        return handle_gcp_exception(
            exc, operation=f"GCS bucket scan for {project_id}"
        )
