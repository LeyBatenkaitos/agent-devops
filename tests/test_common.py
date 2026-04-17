"""Unit tests for tools/_common.py shared helpers."""

from __future__ import annotations

import json

from tools._common import (
    Finding,
    as_tool_result,
    error_result,
    handle_gcp_exception,
)


def test_as_tool_result_envelope() -> None:
    findings = [
        Finding("HIGH", "projects/p", "iam.primitive_role", "msg", "rec"),
    ]
    payload = json.loads(as_tool_result(findings, summary="done"))
    assert payload["status"] == "success"
    assert payload["findings_count"] == 1
    assert payload["summary"] == "done"
    assert payload["findings"][0]["severity"] == "HIGH"
    assert payload["findings"][0]["category"] == "iam.primitive_role"


def test_error_result_includes_hint() -> None:
    payload = json.loads(error_result("boom", hint="try this"))
    assert payload == {"status": "error", "message": "boom", "hint": "try this"}


def test_handle_gcp_exception_credentials(credentials_error) -> None:  # type: ignore[no-untyped-def]
    payload = json.loads(handle_gcp_exception(credentials_error, operation="scan"))
    assert payload["status"] == "error"
    assert "Application Default Credentials" in payload["message"]
    assert "gcloud auth application-default login" in payload["hint"]


def test_handle_gcp_exception_permission_denied() -> None:
    from google.api_core.exceptions import PermissionDenied

    payload = json.loads(
        handle_gcp_exception(PermissionDenied("nope"), operation="scan")
    )
    assert payload["status"] == "error"
    assert "roles/iam.securityReviewer" in payload["hint"]


def test_handle_gcp_exception_api_disabled_is_distinguished() -> None:
    """PermissionDenied sometimes actually means 'API is disabled'.

    Owner / editor roles cannot fix that — the hint must point the user to
    enabling the API, not to requesting permissions.
    """

    from google.api_core.exceptions import PermissionDenied

    exc = PermissionDenied(
        "Cloud Run Admin API has not been used in project foo before or it is "
        "disabled. Enable it by visiting https://console.developers.google.com/"
        "apis/api/run.googleapis.com/overview?project=foo"
    )
    payload = json.loads(handle_gcp_exception(exc, operation="scan"))
    assert payload["status"] == "error"
    assert "API is not enabled" in payload["message"]
    assert "gcloud services enable run.googleapis.com" in payload["hint"]
