"""Smoke test: run each GCP tool against a real project using ADC.

Usage:
    venv/bin/python scripts/smoke_test_gcp.py PROJECT_ID

Prints each tool's JSON response truncated for readability and reports
which tools returned status=success vs status=error. Does not call any LLM.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running the script directly from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.gcp_cloudrun import scan_cloudrun_services
from tools.gcp_compute import analyze_gcp_infra
from tools.gcp_iam import audit_gcp_service_account_keys, scan_gcp_iam_roles
from tools.gcp_network import scan_gcp_network
from tools.gcp_storage import scan_gcs_buckets


def _run(name: str, fn, *args, **kwargs) -> None:
    print(f"\n===== {name} =====")
    try:
        raw = fn(*args, **kwargs)
    except Exception as exc:
        print(f"UNEXPECTED EXCEPTION: {exc!r}")
        return

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print("non-JSON output:")
        print(raw)
        return

    status = payload.get("status")
    count = payload.get("findings_count", "-")
    summary = payload.get("summary") or payload.get("message") or ""
    hint = payload.get("hint", "")
    print(f"status={status} findings={count}")
    if summary:
        print(f"summary: {summary}")
    if hint:
        print(f"hint: {hint}")

    findings = payload.get("findings", [])
    for f in findings[:5]:
        print(
            f"  [{f.get('severity')}] {f.get('category')}: {f.get('message')}"
        )
    if len(findings) > 5:
        print(f"  ... {len(findings) - 5} more")


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: smoke_test_gcp.py PROJECT_ID")
        sys.exit(2)
    project = sys.argv[1]

    print(f"Smoke-testing GCP tools against project: {project}")

    _run("scan_gcp_iam_roles", scan_gcp_iam_roles, project)
    _run("audit_gcp_service_account_keys", audit_gcp_service_account_keys, project)
    _run("analyze_gcp_infra (all zones)", analyze_gcp_infra, project)
    _run("scan_gcs_buckets", scan_gcs_buckets, project)
    _run("scan_cloudrun_services", scan_cloudrun_services, project)
    _run("scan_gcp_network", scan_gcp_network, project)


if __name__ == "__main__":
    main()
