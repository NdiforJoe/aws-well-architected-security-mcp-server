from unittest.mock import patch, MagicMock
import pytest

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