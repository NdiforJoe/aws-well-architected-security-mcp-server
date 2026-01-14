def map_to_nist_soc2(findings: list[dict]) -> list[dict]:
    """
    Map security findings to NIST CSF 2.0 and SOC 2 Trust Services Criteria (TSC).
    
    NIST CSF 2.0 Functions:
    - ID: Identify
    - PR: Protect
    - DE: Detect
    - RS: Respond
    - RC: Recover
    
    SOC 2 Trust Services Criteria:
    - CC: Common Criteria (CC6 = Logical Access, CC7 = System Operations)
    """
    nist_soc_map = {
        # IAM & Access Controls
        "IAM-ROOT-MFA": {
            "nist_csf": "PR.AC-01",
            "nist_function": "Protect",
            "soc2": "CC6.1",
            "description": "Identities and credentials are issued, managed, verified, revoked, and audited"
        },
        "IAM-ROOT-KEYS": {
            "nist_csf": "PR.AC-01",
            "nist_function": "Protect",
            "soc2": "CC6.1",
            "description": "Root account access keys pose critical security risk"
        },
        "IAM-PASSWORD-POLICY": {
            "nist_csf": "PR.AC-01",
            "nist_function": "Protect",
            "soc2": "CC6.1",
            "description": "Password policies enforce strong authentication"
        },
        "IAM-USER-MFA": {
            "nist_csf": "PR.AC-07",
            "nist_function": "Protect",
            "soc2": "CC6.2",
            "description": "Users are authenticated and authorized to access the system"
        },
        
        # Logging & Monitoring
        "CLOUDTRAIL-NOT-MULTI-REGION": {
            "nist_csf": "DE.AE-03",
            "nist_function": "Detect",
            "soc2": "CC7.2",
            "description": "Event data are collected and correlated from multiple sources"
        },
        "CLOUDTRAIL-NOT-ENCRYPTED": {
            "nist_csf": "PR.DS-01",
            "nist_function": "Protect",
            "soc2": "CC6.7",
            "description": "Data-at-rest is protected"
        },
        "CLOUDTRAIL-LOG-VALIDATION": {
            "nist_csf": "PR.PT-01",
            "nist_function": "Protect",
            "soc2": "CC7.2",
            "description": "Audit/log records are protected from unauthorized access"
        },
        "CLOUDWATCH-ALARMS": {
            "nist_csf": "DE.CM-07",
            "nist_function": "Detect",
            "soc2": "CC7.2",
            "description": "Monitoring for unauthorized activity is continuous"
        },
        
        # Network Security
        "VPC-FLOW-LOGS": {
            "nist_csf": "DE.AE-03",
            "nist_function": "Detect",
            "soc2": "CC6.6",
            "description": "Network traffic is logged and monitored"
        },
        "SECURITY-GROUP-OPEN": {
            "nist_csf": "PR.AC-05",
            "nist_function": "Protect",
            "soc2": "CC6.6",
            "description": "Network integrity is protected"
        },
        "NACL-INGRESS-22": {
            "nist_csf": "PR.AC-05",
            "nist_function": "Protect",
            "soc2": "CC6.6",
            "description": "Physical access to network resources is restricted"
        },
        
        # Encryption
        "S3-BUCKET-ENCRYPTION": {
            "nist_csf": "PR.DS-01",
            "nist_function": "Protect",
            "soc2": "CC6.7",
            "description": "Data-at-rest is protected using encryption"
        },
        "EBS-ENCRYPTION": {
            "nist_csf": "PR.DS-01",
            "nist_function": "Protect",
            "soc2": "CC6.7",
            "description": "Storage volumes are encrypted"
        },
        "RDS-ENCRYPTION": {
            "nist_csf": "PR.DS-01",
            "nist_function": "Protect",
            "soc2": "CC6.7",
            "description": "Database encryption at rest"
        },
        
        # Security Services
        "GUARDDUTY-NOT-ENABLED": {
            "nist_csf": "DE.CM-01",
            "nist_function": "Detect",
            "soc2": "CC7.2",
            "description": "Networks and network services are monitored continuously"
        },
        "GUARDDUTY-ENABLED": {
            "nist_csf": "DE.CM-01",
            "nist_function": "Detect",
            "soc2": "CC7.2",
            "description": "Threat detection is active and monitoring continuously"
        },
        "SECURITYHUB-NOT-ENABLED": {
            "nist_csf": "ID.RA-01",
            "nist_function": "Identify",
            "soc2": "CC7.1",
            "description": "Asset vulnerabilities are identified and documented"
        },
        "SECURITYHUB-ENABLED": {
            "nist_csf": "ID.RA-01",
            "nist_function": "Identify",
            "soc2": "CC7.1",
            "description": "Security Hub aggregates findings from multiple sources"
        },
        "CONFIG-ENABLED": {
            "nist_csf": "ID.AM-01",
            "nist_function": "Identify",
            "soc2": "CC7.1",
            "description": "Configuration management for system components"
        },
        "INSPECTOR-ENABLED": {
            "nist_csf": "ID.RA-01",
            "nist_function": "Identify",
            "soc2": "CC7.1",
            "description": "Vulnerabilities are identified and documented"
        },
        
        # Data Protection
        "S3-BUCKET-VERSIONING": {
            "nist_csf": "PR.IP-04",
            "nist_function": "Protect",
            "soc2": "A1.2",
            "description": "Backups of information are conducted and protected"
        },
        
        # Secrets Management
        "SECRETS-MANAGER": {
            "nist_csf": "PR.AC-01",
            "nist_function": "Protect",
            "soc2": "CC6.1",
            "description": "Secrets and credentials are managed securely"
        },
        "KMS-KEY-ROTATION": {
            "nist_csf": "PR.AC-01",
            "nist_function": "Protect",
            "soc2": "CC6.1",
            "description": "Encryption keys are rotated regularly"
        }
    }
    
    # Apply mappings to findings
    for finding in findings:
        finding_id = finding.get("id", "")
        
        # Check for exact match first
        if finding_id in nist_soc_map:
            mapping = nist_soc_map[finding_id]
            finding["nist_csf"] = mapping["nist_csf"]
            finding["nist_function"] = mapping.get("nist_function", "Unknown")
            finding["soc2"] = mapping["soc2"]
            finding["compliance_description"] = mapping.get("description", "")
        
        # Handle dynamic finding IDs (with resource identifiers)
        elif finding_id.startswith("KMS-ROTATION-DISABLED-"):
            finding["nist_csf"] = "PR.AC-01"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.1"
            finding["compliance_description"] = "Encryption keys are rotated regularly to limit cryptographic exposure"
        
        elif finding_id.startswith("SG-DEFAULT-OPEN-"):
            finding["nist_csf"] = "PR.AC-05"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.6"
            finding["compliance_description"] = "Network integrity is protected and public access is restricted"
        
        elif finding_id.startswith("S3-PUBLIC-"):
            finding["nist_csf"] = "PR.AC-04"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.6"
            finding["compliance_description"] = "Access permissions are managed and enforced to prevent unauthorized data access"
        
        elif finding_id.startswith("EBS-UNENCRYPTED-"):
            finding["nist_csf"] = "PR.DS-01"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.7"
            finding["compliance_description"] = "Data-at-rest is protected using encryption"
        
        elif finding_id.startswith("RDS-UNENCRYPTED-"):
            finding["nist_csf"] = "PR.DS-01"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.7"
            finding["compliance_description"] = "Database encryption at rest protects sensitive information"
        
        elif finding_id.startswith("EC2-PUBLIC-IP-"):
            finding["nist_csf"] = "PR.AC-05"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.6"
            finding["compliance_description"] = "Network boundaries are protected from unauthorized external access"
        
        elif finding_id.startswith("LAMBDA-FUNCTION-"):
            finding["nist_csf"] = "PR.AC-04"
            finding["nist_function"] = "Protect"
            finding["soc2"] = "CC6.3"
            finding["compliance_description"] = "Access controls are implemented for serverless functions"
        
        else:
            # Default for completely unmapped findings
            finding["nist_csf"] = "Pending"
            finding["nist_function"] = "Review Required"
            finding["soc2"] = "Pending"
            finding["compliance_description"] = "This finding requires manual compliance review and mapping"
    
    return findings
