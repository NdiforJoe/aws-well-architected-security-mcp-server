from unittest.mock import patch, MagicMock
import pytest
from botocore.exceptions import ClientError

from src.checks import collect_security_findings


@patch('boto3.Session')
def test_collect_security_findings_root_mfa_missing(mock_session):
    # Mock IAM client
    mock_iam = MagicMock()
    mock_session.return_value.client.return_value = mock_iam
    mock_iam.get_account_summary.return_value = {
        'SummaryMap': {'AccountMFAEnabled': 0}
    }

    findings = collect_security_findings("us-east-1", ["IAM"])

    assert len(findings) == 1
    assert findings[0]["id"] == "IAM-ROOT-MFA"
    assert findings[0]["severity"] == "Critical"


@patch('boto3.Session')
def test_collect_security_findings_root_mfa_enabled(mock_session):
    mock_iam = MagicMock()
    mock_session.return_value.client.return_value = mock_iam
    mock_iam.get_account_summary.return_value = {
        'SummaryMap': {'AccountMFAEnabled': 1}
    }

    findings = collect_security_findings("us-east-1", ["IAM"])

    assert len(findings) == 0  # No finding if MFA is enabled

@patch('boto3.Session')
def test_collect_security_findings_root_keys_present(mock_session):
    mock_iam = MagicMock()
    mock_session.return_value.client.return_value = mock_iam
    mock_iam.get_account_summary.return_value = {
        'SummaryMap': {'AccountAccessKeysPresent': 1}
    }

    findings = collect_security_findings("us-east-1", ["IAM"])

    assert any(f["id"] == "IAM-ROOT-KEYS" for f in findings)


@patch('boto3.Session')
def test_collect_security_findings_no_cloudtrail_multi_region(mock_session):
    mock_cloudtrail = MagicMock()
    mock_session.return_value.client.return_value = mock_cloudtrail
    mock_cloudtrail.describe_trails.return_value = {'trailList': [{'IsMultiRegionTrail': False}]}

    findings = collect_security_findings("us-east-1", ["Logging"])

    assert any(f["id"] == "CLOUDTRAIL-NOT-MULTI-REGION" for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_guardduty_not_enabled(mock_session):
    mock_guardduty = MagicMock()
    mock_session.return_value.client.return_value = mock_guardduty
    mock_guardduty.list_detectors.return_value = {'DetectorIds': []}

    findings = collect_security_findings("us-east-1", ["ThreatDetection"])

    assert any(f["id"] == "GUARDDUTY-NOT-ENABLED" for f in findings)


@patch('boto3.Session')
def test_collect_security_findings_securityhub_not_enabled(mock_session):
    mock_securityhub = MagicMock()
    mock_session.return_value.client.return_value = mock_securityhub
    mock_securityhub.describe_hub.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException"}}, "describe_hub"
    )

    findings = collect_security_findings("us-east-1", ["Compliance"])

    assert any(f["id"] == "SECURITYHUB-NOT-ENABLED" for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_cloudtrail_not_multi_region(mock_session):
    mock_cloudtrail = MagicMock()
    mock_session.return_value.client.return_value = mock_cloudtrail
    mock_cloudtrail.describe_trails.return_value = {'trailList': [{'IsMultiRegionTrail': False}]}

    findings = collect_security_findings("us-east-1", ["Logging"])

    assert any(f["id"] == "CLOUDTRAIL-NOT-MULTI-REGION" for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_s3_public_bucket(mock_session):
    mock_s3 = MagicMock()
    mock_session.return_value.client.return_value = mock_s3
    mock_s3.list_buckets.return_value = {'Buckets': [{'Name': 'test-public'}]}
    mock_s3.get_bucket_acl.return_value = {
        'Grants': [{'Grantee': {'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'}}]
    }

    findings = collect_security_findings("us-east-1", ["Storage"])

    assert any("S3-PUBLIC-test-public" in f["id"] for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_guardduty_not_enabled(mock_session):
    mock_guardduty = MagicMock()
    mock_session.return_value.client.return_value = mock_guardduty
    mock_guardduty.list_detectors.return_value = {'DetectorIds': []}

    findings = collect_security_findings("us-east-1", ["ThreatDetection"])

    assert any(f["id"] == "GUARDDUTY-NOT-ENABLED" for f in findings)


@patch('boto3.Session')
def test_collect_security_findings_kms_rotation_disabled(mock_session):
    mock_kms = MagicMock()
    mock_session.return_value.client.return_value = mock_kms
    mock_kms.list_keys.return_value = {'Keys': [{'KeyId': 'test-key-123'}]}
    mock_kms.get_key_rotation_status.return_value = {'KeyRotationEnabled': False}

    findings = collect_security_findings("us-east-1", ["Encryption"])

    assert any("KMS-ROTATION-DISABLED" in f["id"] for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_kms_rotation_disabled(mock_session):
    mock_kms = MagicMock()
    mock_session.return_value.client.return_value = mock_kms
    mock_kms.list_keys.return_value = {'Keys': [{'KeyId': 'test-key-123'}]}
    mock_kms.get_key_rotation_status.return_value = {'KeyRotationEnabled': False}

    findings = collect_security_findings("us-east-1", ["Encryption"])

    assert any("KMS-ROTATION-DISABLED" in f["id"] for f in findings)


@patch('boto3.Session')
def test_collect_security_findings_securityhub_not_enabled(mock_session):
    mock_securityhub = MagicMock()
    mock_session.return_value.client.return_value = mock_securityhub
    mock_securityhub.describe_hub.side_effect = ClientError(
        {"Error": {"Code": "ResourceNotFoundException"}}, "describe_hub"
    )

    findings = collect_security_findings("us-east-1", ["Compliance"])

    assert any(f["id"] == "SECURITYHUB-NOT-ENABLED" for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_guardduty_not_enabled(mock_session):
    mock_guardduty = MagicMock()
    mock_session.return_value.client.return_value = mock_guardduty
    mock_guardduty.list_detectors.return_value = {'DetectorIds': []}

    findings = collect_security_findings("us-east-1", ["ThreatDetection"])

    assert any(f["id"] == "GUARDDUTY-NOT-ENABLED" for f in findings)


@patch('boto3.Session')
def test_collect_security_findings_kms_rotation_disabled(mock_session):
    mock_kms = MagicMock()
    mock_session.return_value.client.return_value = mock_kms
    mock_kms.list_keys.return_value = {'Keys': [{'KeyId': 'test-key-123'}]}
    mock_kms.get_key_rotation_status.return_value = {'KeyRotationEnabled': False}

    findings = collect_security_findings("us-east-1", ["Encryption"])

    assert any("KMS-ROTATION-DISABLED" in f["id"] for f in findings)

@patch('boto3.Session')
def test_collect_security_findings_guardduty_not_enabled(mock_session):
    mock_guardduty = MagicMock()
    mock_session.return_value.client.return_value = mock_guardduty
    mock_guardduty.list_detectors.return_value = {'DetectorIds': []}

    findings = collect_security_findings("us-east-1", ["ThreatDetection"])

    assert any(f["id"] == "GUARDDUTY-NOT-ENABLED" for f in findings)


@patch('boto3.Session')
def test_collect_security_findings_kms_rotation_disabled(mock_session):
    mock_kms = MagicMock()
    mock_session.return_value.client.return_value = mock_kms
    mock_kms.list_keys.return_value = {'Keys': [{'KeyId': 'test-key-123'}]}
    mock_kms.get_key_rotation_status.return_value = {'KeyRotationEnabled': False}

    findings = collect_security_findings("us-east-1", ["Encryption"])

    assert any("KMS-ROTATION-DISABLED" in f["id"] for f in findings)