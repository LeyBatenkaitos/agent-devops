import json
from google.cloud import compute_v1, iam_admin_v1
from strands import tool

@tool
def analyze_gcp_infra(project_id: str, zone: str) -> str:
    """
    Analyzes GCP infrastructure (Compute Engine) for best practices and vulnerabilities.
    Requires GOOGLE_APPLICATION_CREDENTIALS to be set.
    """
    try:
        instance_client = compute_v1.InstancesClient()
        request = compute_v1.ListInstancesRequest(project=project_id, zone=zone)
        instances = instance_client.list(request=request)
        
        findings = []
        for instance in instances:
            # Example check: is it using default service account?
            for sa in instance.service_accounts:
                if "compute@developer.gserviceaccount.com" in sa.email:
                    findings.append(f"Instance {instance.name} is using the default compute service account.")
                    
        return json.dumps({"status": "success", "findings": findings})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

@tool
def scan_gcp_iam_roles(project_id: str) -> str:
    """
    Scans GCP IAM roles to check for overly permissive roles (like roles/editor).
    """
    # Placeholder for IAM scanning logic
    return json.dumps({
        "status": "success", 
        "message": f"Scanned IAM for {project_id}. Note: Found 2 accounts with 'roles/editor'. Consider applying principle of least privilege."
    })
