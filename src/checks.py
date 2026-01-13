import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

def collect_security_findings(region: str, focus_areas: list[str] = None) -> list[dict]:
    """Collect read-only security findings from AWS services."""
    if focus_areas is None:
        focus_areas = ["IAM", "Logging", "Network", "Storage", "Encryption", "ThreatDetection"]

    findings = []
    session = boto3.Session(region_name=region)

    try:
        # 1. IAM: Root MFA missing
        if "IAM" in focus_areas:
            iam = session.client('iam')
            summary = iam.get_account_summary()['SummaryMap']
            if summary.get('AccountMFAEnabled', 0) == 0:
                findings.append({
                    "id": "IAM-ROOT-MFA",
                    "severity": "Critical",
                    "description": "Root account does not have MFA enabled",
                    "resource": "Root User",
                    "remediation": "Enable hardware MFA via IAM console or CLI: aws iam enable-mfa-device ..."
                })

            # 2. IAM: Root has active access keys
            if summary.get('AccountAccessKeysPresent', 0) > 0:
                findings.append({
                    "id": "IAM-ROOT-KEYS",
                    "severity": "Critical",
                    "description": "Root account has active access keys",
                    "resource": "Root User",
                    "remediation": "Delete root access keys immediately via IAM console"
                })

        # 3. Logging: CloudTrail not multi-region
        if "Logging" in focus_areas:
            cloudtrail = session.client('cloudtrail')
            trails = cloudtrail.describe_trails()['trailList']
            if not trails or not any(t.get('IsMultiRegionTrail', False) for t in trails):
                findings.append({
                    "id": "CLOUDTRAIL-NOT-MULTI-REGION",
                    "severity": "High",
                    "description": "No multi-region CloudTrail trail configured",
                    "resource": "CloudTrail",
                    "remediation": "Create multi-region trail: aws cloudtrail create-trail --is-multi-region-trail ..."
                })

        # 4. Network: Default security groups allow all traffic
        if "Network" in focus_areas:
            ec2 = session.client('ec2')
            sgs = ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': ['default']}]
            )['SecurityGroups']
            for sg in sgs:
                for perm in sg.get('IpPermissions', []):
                    if any(r['CidrIp'] == '0.0.0.0/0' for r in perm.get('IpRanges', [])):
                        findings.append({
                            "id": f"SG-DEFAULT-OPEN-{sg['GroupId']}",
                            "severity": "High",
                            "description": f"Default security group {sg['GroupId']} allows public ingress",
                            "resource": sg['GroupId'],
                            "remediation": "Revoke public ingress: aws ec2 revoke-security-group-ingress ..."
                        })

        # 5. Storage: S3 buckets have public access
        if "Storage" in focus_areas:
            s3 = session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                    public = any(g['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' for g in acl['Grants'])
                    if public:
                        findings.append({
                            "id": f"S3-PUBLIC-{bucket['Name']}",
                            "severity": "Critical",
                            "description": f"S3 bucket {bucket['Name']} has public ACL",
                            "resource": bucket['Name'],
                            "remediation": "Block public access: aws s3api put-public-access-block ..."
                        })
                except ClientError:
                    pass  # Skip if no permission

        # 6. Encryption: KMS keys without rotation
        if "Encryption" in focus_areas:
            kms = session.client('kms')
            keys = kms.list_keys()['Keys']
            for key in keys:
                try:
                    rotation = kms.get_key_rotation_status(KeyId=key['KeyId'])
                    if not rotation.get('KeyRotationEnabled', False):
                        findings.append({
                            "id": f"KMS-ROTATION-DISABLED-{key['KeyId'][:8]}",
                            "severity": "Medium",
                            "description": f"KMS key {key['KeyId']} does not have automatic rotation",
                            "resource": key['KeyId'],
                            "remediation": "Enable rotation: aws kms enable-key-rotation --key-id ..."
                        })
                except ClientError:
                    pass

        # 7. Threat Detection: GuardDuty not enabled
        if "ThreatDetection" in focus_areas:
            guardduty = session.client('guardduty')
            detectors = guardduty.list_detectors()['DetectorIds']
            if not detectors:
                findings.append({
                    "id": "GUARDDUTY-NOT-ENABLED",
                    "severity": "High",
                    "description": "GuardDuty is not enabled in this region",
                    "resource": "GuardDuty",
                    "remediation": "Enable GuardDuty: aws guardduty create-detector --enable ..."
                })

        # 8. Compliance Hub: Security Hub not enabled
        if "Compliance" in focus_areas:
            securityhub = session.client('securityhub')
            try:
                hub = securityhub.describe_hub()
                if not hub.get('HubArn'):
                    findings.append({
                        "id": "SECURITYHUB-NOT-ENABLED",
                        "severity": "High",
                        "description": "Security Hub is not enabled",
                        "resource": "Security Hub",
                        "remediation": "Enable Security Hub: aws securityhub enable-security-hub ..."
                    })
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    findings.append({
                        "id": "SECURITYHUB-NOT-ENABLED",
                        "severity": "High",
                        "description": "Security Hub is not enabled",
                        "resource": "Security Hub",
                        "remediation": "Enable Security Hub: aws securityhub enable-security-hub ..."
                    })

    except ClientError as e:
        logger.warning(f"API error in region {region}: {e}")

    return findings