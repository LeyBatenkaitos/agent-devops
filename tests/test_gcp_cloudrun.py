"""Unit tests for tools/gcp_cloudrun.py."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _make_service(name: str, sa: str, annotations: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        annotations=annotations or {},
        template=SimpleNamespace(service_account=sa),
    )


def test_scan_cloudrun_flags_unauth_and_default_sa() -> None:
    from tools import gcp_cloudrun

    service = _make_service(
        name="projects/p/locations/us-central1/services/svc-1",
        sa="1234-compute@developer.gserviceaccount.com",
    )
    policy = SimpleNamespace(
        bindings=[SimpleNamespace(role="roles/run.invoker", members=["allUsers"])]
    )

    with patch.object(gcp_cloudrun.run_v2, "ServicesClient") as client_cls:
        client = MagicMock()
        client.list_services.return_value = [service]
        client.get_iam_policy.return_value = policy
        client_cls.return_value = client
        payload = json.loads(gcp_cloudrun.scan_cloudrun_services("proj"))

    categories = {f["category"] for f in payload["findings"]}
    assert {
        "cloudrun.unauthenticated_invoker",
        "cloudrun.default_service_account",
        "cloudrun.iap_not_enabled",
        "cloudrun.region_out_of_standard",
    }.issubset(categories)


def test_scan_cloudrun_accepts_iap_enabled_service() -> None:
    from tools import gcp_cloudrun

    service = _make_service(
        name="projects/p/locations/us-east1/services/svc-ok",
        sa="dedicated@proj.iam.gserviceaccount.com",
        annotations={"run.googleapis.com/iap-enabled": "true"},
    )
    policy = SimpleNamespace(bindings=[])
    with patch.object(gcp_cloudrun.run_v2, "ServicesClient") as client_cls:
        client = MagicMock()
        client.list_services.return_value = [service]
        client.get_iam_policy.return_value = policy
        client_cls.return_value = client
        payload = json.loads(gcp_cloudrun.scan_cloudrun_services("proj"))

    assert payload["status"] == "success"
    assert payload["findings_count"] == 0


def test_scan_cloudrun_empty_project() -> None:
    from tools import gcp_cloudrun

    payload = json.loads(gcp_cloudrun.scan_cloudrun_services(""))
    assert payload["status"] == "error"
