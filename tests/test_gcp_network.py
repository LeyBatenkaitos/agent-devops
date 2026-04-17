"""Unit tests for tools/gcp_network.py."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _network(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


def _firewall(
    name: str,
    *,
    direction: str = "INGRESS",
    sources: list[str] | None = None,
    protocol: str = "tcp",
    ports: list[str] | None = None,
    logging_enabled: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        direction=direction,
        source_ranges=sources or [],
        allowed=[SimpleNamespace(I_p_protocol=protocol, ports=ports or [])],
        log_config=SimpleNamespace(enable=logging_enabled),
    )


def test_scan_network_flags_open_ingress_and_default_vpc() -> None:
    from tools import gcp_network

    with (
        patch.object(gcp_network.compute_v1, "NetworksClient") as net_cls,
        patch.object(gcp_network.compute_v1, "FirewallsClient") as fw_cls,
    ):
        net_client = MagicMock()
        net_client.list.return_value = [_network("default"), _network("custom-vpc")]
        net_cls.return_value = net_client

        fw_client = MagicMock()
        fw_client.list.return_value = [
            _firewall("allow-ssh-world", sources=["0.0.0.0/0"], ports=["22"]),
            _firewall("allow-all", sources=["0.0.0.0/0"], protocol="all", ports=[]),
            _firewall("internal-only", sources=["10.0.0.0/8"], ports=["5432"], logging_enabled=False),
        ]
        fw_cls.return_value = fw_client

        payload = json.loads(gcp_network.scan_gcp_network("proj"))

    categories = {f["category"] for f in payload["findings"]}
    assert "network.default_vpc_in_use" in categories
    assert "network.firewall_open_to_world" in categories
    assert "network.firewall_logging_disabled" in categories

    severities = [
        f["severity"]
        for f in payload["findings"]
        if f["category"] == "network.firewall_open_to_world"
    ]
    assert "CRITICAL" in severities  # allow-all rule


def test_scan_network_empty_project() -> None:
    from tools import gcp_network

    payload = json.loads(gcp_network.scan_gcp_network(""))
    assert payload["status"] == "error"
