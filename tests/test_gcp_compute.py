"""Unit tests for tools/gcp_compute.py."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _instance(**overrides) -> SimpleNamespace:  # type: ignore[no-untyped-def]
    defaults = dict(
        name="vm-1",
        network_interfaces=[],
        service_accounts=[],
        metadata=SimpleNamespace(items=[]),
        shielded_instance_config=SimpleNamespace(
            enable_secure_boot=True,
            enable_vtpm=True,
            enable_integrity_monitoring=True,
        ),
        can_ip_forward=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_analyze_gcp_infra_flags_public_ip_and_default_sa() -> None:
    from tools import gcp_compute

    public_nic = SimpleNamespace(
        name="nic0",
        access_configs=[SimpleNamespace(nat_i_p="34.120.0.1", type_="ONE_TO_ONE_NAT")],
    )
    instance = _instance(
        network_interfaces=[public_nic],
        service_accounts=[SimpleNamespace(email="1234-compute@developer.gserviceaccount.com")],
    )
    with patch.object(gcp_compute.compute_v1, "InstancesClient") as client_cls:
        client = MagicMock()
        client.list.return_value = [instance]
        client_cls.return_value = client
        payload = json.loads(gcp_compute.analyze_gcp_infra("proj", zone="us-east1-b"))

    categories = {f["category"] for f in payload["findings"]}
    assert "compute.public_ip" in categories
    assert "compute.default_service_account" in categories
    assert "compute.os_login_disabled" in categories


def test_analyze_gcp_infra_empty_project_id_returns_error() -> None:
    from tools import gcp_compute

    payload = json.loads(gcp_compute.analyze_gcp_infra(""))
    assert payload["status"] == "error"


def test_analyze_gcp_infra_handles_permission_denied() -> None:
    from google.api_core.exceptions import PermissionDenied

    from tools import gcp_compute

    with patch.object(gcp_compute.compute_v1, "InstancesClient") as client_cls:
        client = MagicMock()
        client.aggregated_list.side_effect = PermissionDenied("nope")
        client_cls.return_value = client
        payload = json.loads(gcp_compute.analyze_gcp_infra("proj"))

    assert payload["status"] == "error"
    assert "roles/iam.securityReviewer" in payload["hint"]


def test_analyze_gcp_infra_flags_shielded_vm_off() -> None:
    from tools import gcp_compute

    instance = _instance(
        metadata=SimpleNamespace(
            items=[
                SimpleNamespace(key="enable-oslogin", value="TRUE"),
                SimpleNamespace(key="block-project-ssh-keys", value="TRUE"),
            ]
        ),
        shielded_instance_config=SimpleNamespace(
            enable_secure_boot=False,
            enable_vtpm=True,
            enable_integrity_monitoring=True,
        ),
        can_ip_forward=True,
    )
    with patch.object(gcp_compute.compute_v1, "InstancesClient") as client_cls:
        client = MagicMock()
        client.list.return_value = [instance]
        client_cls.return_value = client
        payload = json.loads(gcp_compute.analyze_gcp_infra("proj", zone="us-east1-b"))

    categories = {f["category"] for f in payload["findings"]}
    assert "compute.shielded_vm_disabled" in categories
    assert "compute.ip_forwarding_enabled" in categories
