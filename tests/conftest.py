"""Shared fixtures and test helpers.

The GCP tool modules import client libraries at module import time. In CI or
local environments without those packages installed, we stub the relevant
namespaces with SimpleNamespace so the imports still succeed. Each test then
patches the specific client classes it cares about.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _ensure_module(dotted_name: str) -> types.ModuleType:
    """Register (or fetch) a dummy module path like 'google.cloud.compute_v1'."""

    if dotted_name in sys.modules:
        return sys.modules[dotted_name]
    module = types.ModuleType(dotted_name)
    sys.modules[dotted_name] = module
    parent_name, _, child_name = dotted_name.rpartition(".")
    if parent_name:
        parent = _ensure_module(parent_name)
        setattr(parent, child_name, module)
    return module


def _install_strands_stub() -> None:
    if "strands" in sys.modules:
        return
    strands_mod = types.ModuleType("strands")

    def tool(func=None, **_kwargs):  # type: ignore[no-untyped-def]
        if func is None:
            return lambda f: f
        return func

    strands_mod.tool = tool  # type: ignore[attr-defined]
    sys.modules["strands"] = strands_mod


def _install_google_stubs() -> None:
    # google.auth.exceptions
    auth_exc = _ensure_module("google.auth.exceptions")

    class DefaultCredentialsError(Exception):
        pass

    auth_exc.DefaultCredentialsError = DefaultCredentialsError

    # google.api_core.exceptions
    api_exc = _ensure_module("google.api_core.exceptions")

    class GoogleAPICallError(Exception):
        def __init__(self, message: str = "") -> None:
            super().__init__(message)
            self.message = message

    class PermissionDenied(GoogleAPICallError):
        pass

    class NotFound(GoogleAPICallError):
        pass

    api_exc.GoogleAPICallError = GoogleAPICallError
    api_exc.PermissionDenied = PermissionDenied
    api_exc.NotFound = NotFound

    # google.cloud.compute_v1
    compute_mod = _ensure_module("google.cloud.compute_v1")
    compute_mod.InstancesClient = MagicMock  # type: ignore[attr-defined]
    compute_mod.NetworksClient = MagicMock  # type: ignore[attr-defined]
    compute_mod.FirewallsClient = MagicMock  # type: ignore[attr-defined]
    compute_mod.ListInstancesRequest = lambda **kw: SimpleNamespace(**kw)  # type: ignore[attr-defined]
    compute_mod.AggregatedListInstancesRequest = lambda **kw: SimpleNamespace(**kw)  # type: ignore[attr-defined]
    compute_mod.Metadata = SimpleNamespace  # type: ignore[attr-defined]
    compute_mod.Instance = SimpleNamespace  # type: ignore[attr-defined]
    compute_mod.Firewall = SimpleNamespace  # type: ignore[attr-defined]

    # google.cloud.resourcemanager_v3
    rm_mod = _ensure_module("google.cloud.resourcemanager_v3")
    rm_mod.ProjectsClient = MagicMock  # type: ignore[attr-defined]

    # google.cloud.iam_admin_v1
    iam_mod = _ensure_module("google.cloud.iam_admin_v1")
    iam_mod.IAMClient = MagicMock  # type: ignore[attr-defined]

    class _ListServiceAccountKeysRequest:
        class KeyType:
            USER_MANAGED = "USER_MANAGED"

    iam_mod.ListServiceAccountKeysRequest = _ListServiceAccountKeysRequest  # type: ignore[attr-defined]

    # google.cloud.storage
    storage_mod = _ensure_module("google.cloud.storage")
    storage_mod.Client = MagicMock  # type: ignore[attr-defined]
    storage_mod.Bucket = SimpleNamespace  # type: ignore[attr-defined]

    # google.cloud.run_v2
    run_mod = _ensure_module("google.cloud.run_v2")
    run_mod.ServicesClient = MagicMock  # type: ignore[attr-defined]
    run_mod.Service = SimpleNamespace  # type: ignore[attr-defined]


_install_strands_stub()
_install_google_stubs()


@pytest.fixture
def credentials_error():
    from google.auth.exceptions import DefaultCredentialsError

    return DefaultCredentialsError("no ADC configured")
