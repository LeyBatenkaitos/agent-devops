"""Unit tests for tools/gcp_iam.py."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _binding(role: str, members: list[str]) -> SimpleNamespace:
    return SimpleNamespace(role=role, members=members)


def test_scan_gcp_iam_roles_flags_primitive_roles() -> None:
    from tools import gcp_iam

    fake_policy = SimpleNamespace(
        bindings=[
            _binding("roles/editor", ["user:alice@example.com"]),
            _binding("roles/viewer", ["group:team@example.com"]),
            _binding("roles/run.invoker", ["serviceAccount:foo@bar.iam.gserviceaccount.com"]),
        ]
    )
    with patch.object(gcp_iam.resourcemanager_v3, "ProjectsClient") as client_cls:
        client_cls.return_value.get_iam_policy.return_value = fake_policy
        payload = json.loads(gcp_iam.scan_gcp_iam_roles("my-proj"))

    assert payload["status"] == "success"
    categories = {f["category"] for f in payload["findings"]}
    assert categories == {"iam.primitive_role"}
    severities = {f["severity"] for f in payload["findings"]}
    # Editor + user member is escalated to CRITICAL; viewer binding is MEDIUM
    assert "CRITICAL" in severities
    assert "MEDIUM" in severities
    assert payload["findings_count"] == 2


def test_scan_gcp_iam_roles_rejects_empty_project_id() -> None:
    from tools import gcp_iam

    payload = json.loads(gcp_iam.scan_gcp_iam_roles(""))
    assert payload["status"] == "error"
    assert "project_id" in payload["message"]


def test_scan_gcp_iam_roles_handles_credentials_error(credentials_error) -> None:  # type: ignore[no-untyped-def]
    from tools import gcp_iam

    with patch.object(gcp_iam.resourcemanager_v3, "ProjectsClient") as client_cls:
        client_cls.return_value.get_iam_policy.side_effect = credentials_error
        payload = json.loads(gcp_iam.scan_gcp_iam_roles("my-proj"))
    assert payload["status"] == "error"
    assert "Application Default Credentials" in payload["message"]


def test_audit_service_account_keys_flags_user_managed() -> None:
    from datetime import datetime, timedelta, timezone

    from tools import gcp_iam

    account = SimpleNamespace(
        email="sa@my-proj.iam.gserviceaccount.com",
        name="projects/my-proj/serviceAccounts/sa@my-proj.iam.gserviceaccount.com",
    )
    fresh_key = SimpleNamespace(
        name="keys/fresh",
        valid_after_time=datetime.now(timezone.utc) - timedelta(days=10),
    )
    stale_key = SimpleNamespace(
        name="keys/stale",
        valid_after_time=datetime.now(timezone.utc) - timedelta(days=200),
    )

    with patch.object(gcp_iam.iam_admin_v1, "IAMClient") as client_cls:
        client = MagicMock()
        client.list_service_accounts.return_value = SimpleNamespace(accounts=[account])
        client.list_service_account_keys.return_value = SimpleNamespace(
            keys=[fresh_key, stale_key]
        )
        client_cls.return_value = client
        payload = json.loads(gcp_iam.audit_gcp_service_account_keys("my-proj"))

    severities = [f["severity"] for f in payload["findings"]]
    assert "MEDIUM" in severities
    assert "HIGH" in severities
    assert payload["findings_count"] == 2
