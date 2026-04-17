"""Unit tests for tools/gcp_storage.py."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _make_bucket(name: str, *, ubla: bool, pap: str | None, public_role: str | None) -> MagicMock:
    bucket = MagicMock()
    bucket.name = name
    bucket.iam_configuration = SimpleNamespace(
        uniform_bucket_level_access_enabled=ubla,
        public_access_prevention=pap,
    )
    bucket.default_kms_key_name = None
    bucket.versioning_enabled = False
    bucket.logging = {}
    bindings: list[dict] = []
    if public_role:
        bindings.append({"role": public_role, "members": ["allUsers"]})
    bucket.get_iam_policy.return_value = SimpleNamespace(bindings=bindings)
    bucket.reload = MagicMock()
    return bucket


def test_scan_gcs_buckets_flags_public_and_weak_config() -> None:
    from tools import gcp_storage

    bucket = _make_bucket("my-bucket", ubla=False, pap="inherited", public_role="roles/storage.objectViewer")

    with patch.object(gcp_storage.storage, "Client") as client_cls:
        client = MagicMock()
        client.list_buckets.return_value = [bucket]
        client_cls.return_value = client
        payload = json.loads(gcp_storage.scan_gcs_buckets("proj"))

    categories = {f["category"] for f in payload["findings"]}
    assert {
        "storage.ubla_disabled",
        "storage.public_access_prevention_not_enforced",
        "storage.public_binding",
    }.issubset(categories)


def test_scan_gcs_buckets_empty_project() -> None:
    from tools import gcp_storage

    payload = json.loads(gcp_storage.scan_gcs_buckets(""))
    assert payload["status"] == "error"


def test_scan_gcs_buckets_credentials_error(credentials_error) -> None:  # type: ignore[no-untyped-def]
    from tools import gcp_storage

    with patch.object(gcp_storage.storage, "Client", side_effect=credentials_error):
        payload = json.loads(gcp_storage.scan_gcs_buckets("proj"))
    assert payload["status"] == "error"
    assert "Application Default Credentials" in payload["message"]
