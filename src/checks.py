import boto3
from botocore.exceptions import ClientError

def collect_security_findings(region: str, focus_areas: list[str]) -> list[dict]:
    """Collect security findings from AWS services."""
    findings = []
    session = boto3.Session(region_name=region)

    # IAM Checks (root MFA, etc.)
    if "IAM" in focus_areas:
        iam = session.client('iam')
        try:
            summary = iam.get_account_summary()['SummaryMap']
            if summary.get('AccountMFAEnabled', 0) == 0:
                findings.append({
                    "id": "IAM-ROOT-MFA",
                    "severity": "Critical",
                    "description": "Root account does not have MFA enabled",
                    "resource": "Root User"
                })
        except ClientError as e:
            pass  # Graceful failure if permission denied

    # Add more checks (CloudTrail, Security Groups, etc.) in future iterations

    return findings