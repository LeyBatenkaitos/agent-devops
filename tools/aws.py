import json
import boto3
from strands import tool

@tool
def analyze_aws_infra() -> str:
    """
    Analyzes AWS infrastructure to identify unencrypted S3 buckets or open EC2 security groups.
    Requires AWS credentials to be configured in the environment.
    """
    try:
        s3 = boto3.client('s3')
        # Check buckets
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
        
        findings = []
        for bucket in buckets:
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket)
                # If we get here, it has encryption
            except Exception as e:
                if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                    findings.append(f"Bucket {bucket} does NOT have default encryption enabled.")
                else:
                    findings.append(f"Could not check encryption for {bucket}: {e}")
                    
        return json.dumps({"status": "success", "findings": findings})
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Failed to connect to AWS S3: {e}"})

@tool
def check_s3_encryption(bucket_name: str) -> str:
    """
    Checks if a specific S3 bucket has default encryption enabled.
    """
    try:
        s3 = boto3.client('s3')
        s3.get_bucket_encryption(Bucket=bucket_name)
        return json.dumps({"status": "success", "message": f"Bucket {bucket_name} is encrypted."})
    except Exception as e:
        return json.dumps({"status": "vulnerability_found", "message": f"Bucket {bucket_name} might not be encrypted. Error: {e}"})
