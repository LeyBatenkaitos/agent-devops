"""Backward-compatible shim for legacy imports.

The original `tools/gcp.py` exposed `analyze_gcp_infra` and `scan_gcp_iam_roles`.
These have moved to dedicated modules that implement real checks. This shim
re-exports them so existing callers keep working.
"""

from __future__ import annotations

from tools.gcp_compute import analyze_gcp_infra
from tools.gcp_iam import scan_gcp_iam_roles

__all__ = ["analyze_gcp_infra", "scan_gcp_iam_roles"]
