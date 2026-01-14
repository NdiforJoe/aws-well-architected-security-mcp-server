import boto3
import json
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

def generate_executive_summary(findings: List[Dict], region: str) -> str:
    """
    Use Amazon Bedrock (Nova Pro) to generate an executive summary of security findings.
    
    Args:
        findings: List of security findings
        region: AWS region for the assessment
    
    Returns:
        Executive summary text
    """
    try:
        bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')
        
        # Prepare findings data
        findings_summary = []
        for finding in findings:
            findings_summary.append({
                "id": finding.get("id", "Unknown"),
                "severity": finding.get("severity", "Unknown"),
                "description": finding.get("description", ""),
                "resource": finding.get("resource", ""),
                "nist_csf": finding.get("nist_csf", ""),
                "soc2": finding.get("soc2", "")
            })
        
        # Create prompt
        prompt = f"""You are a Chief Information Security Officer (CISO) reviewing AWS security findings.

Generate a concise executive summary (3-4 paragraphs) for the following security assessment findings in {region}:

{json.dumps(findings_summary, indent=2)}

Your summary should:
1. Start with the overall security posture (Critical/Concerning/Moderate/Good)
2. Highlight the most critical risks and their business impact
3. Provide 2-3 prioritized recommendations
4. Keep it under 200 words and suitable for C-level executives

Be professional, concise, and focus on business risk rather than technical details."""

        # Call Amazon Nova Pro
        response = bedrock.invoke_model(
            modelId='amazon.nova-pro-v1:0',
            contentType='application/json',
            accept='application/json',
            body=json.dumps({
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ],
                "inferenceConfig": {
                    "maxTokens": 500,
                    "temperature": 0.7,
                    "topP": 0.9
                }
            })
        )
        
        # Parse Nova response
        response_body = json.loads(response['body'].read())
        summary = response_body['output']['message']['content'][0]['text']
        
        logger.info("Executive summary generated successfully with Amazon Nova Pro")
        return summary
        
    except Exception as e:
        logger.warning(f"Failed to generate Bedrock summary: {str(e)}")
        return generate_basic_summary(findings, region)


def generate_basic_summary(findings: List[Dict], region: str) -> str:
    """
    Fallback: Generate a basic summary without Bedrock.
    """
    critical_count = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
    high_count = len([f for f in findings if f.get('severity', '').lower() == 'high'])
    medium_count = len([f for f in findings if f.get('severity', '').lower() == 'medium'])
    
    if critical_count > 0:
        posture = "CRITICAL - Immediate Action Required"
    elif high_count > 2:
        posture = "CONCERNING - Prompt Remediation Needed"
    elif high_count > 0:
        posture = "MODERATE - Address High-Priority Issues"
    else:
        posture = "STABLE - Continue Monitoring"
    
    summary = f"""Security Posture Assessment - {region}

Status: {posture}

The security assessment identified {len(findings)} total findings: {critical_count} Critical, {high_count} High, and {medium_count} Medium severity issues.

Key Risks:
- Critical security controls require immediate attention
- Compliance gaps exist in logging and monitoring
- Network security configurations need review

Recommended Actions:
1. Address all Critical findings within 24 hours
2. Implement recommended security controls
3. Schedule follow-up assessment in 7 days
"""
    return summary


def send_critical_findings_notification(findings: List[Dict], sns_topic_arn: str, region: str, use_bedrock: bool = True):
    """
    Send SNS notification for critical and high severity findings with AI-generated executive summary.
    
    Args:
        findings: List of security findings
        sns_topic_arn: ARN of the SNS topic
        region: AWS region for the assessment
        use_bedrock: Whether to use Bedrock for executive summary (default: True)
    """
    # Filter for critical and high severity findings
    critical_findings = [
        f for f in findings 
        if f.get('severity', '').lower() in ['critical', 'high']
    ]
    
    if not critical_findings:
        logger.info("No critical findings to notify")
        return
    
    # Generate executive summary using Bedrock
    if use_bedrock:
        executive_summary = generate_executive_summary(critical_findings, region)
    else:
        executive_summary = generate_basic_summary(critical_findings, region)
    
    # Count findings by severity
    critical_count = len([f for f in critical_findings if f.get('severity', '').lower() == 'critical'])
    high_count = len([f for f in critical_findings if f.get('severity', '').lower() == 'high'])
    
    # Create notification message
    subject = f"🚨 AWS Security Alert: {critical_count} Critical, {high_count} High Priority Findings"
    
    message_lines = [
        "AWS WELL-ARCHITECTED SECURITY ASSESSMENT",
        "=" * 70,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 70,
        executive_summary,
        "",
        "=" * 70,
        "",
        f"DETAILED FINDINGS ({len(critical_findings)} requiring immediate attention)",
        "=" * 70,
        ""
    ]
    
    # Group findings by severity
    critical_only = [f for f in critical_findings if f.get('severity', '').lower() == 'critical']
    high_only = [f for f in critical_findings if f.get('severity', '').lower() == 'high']
    
    if critical_only:
        message_lines.extend([
            "",
            f"🔴 CRITICAL SEVERITY ({len(critical_only)} findings)",
            "-" * 70
        ])
        for finding in critical_only:
            message_lines.extend([
                f"",
                f"Finding: {finding.get('id', 'Unknown')}",
                f"Resource: {finding.get('resource', 'Unknown')}",
                f"Issue: {finding.get('description', 'No description')}",
                f"Compliance: NIST {finding.get('nist_csf', 'N/A')} | SOC 2 {finding.get('soc2', 'N/A')}",
                f"Remediation: {finding.get('remediation', 'No remediation provided')[:150]}...",
                f""
            ])
    
    if high_only:
        message_lines.extend([
            "",
            f"🟠 HIGH SEVERITY ({len(high_only)} findings)",
            "-" * 70
        ])
        for finding in high_only:
            message_lines.extend([
                f"",
                f"Finding: {finding.get('id', 'Unknown')}",
                f"Resource: {finding.get('resource', 'Unknown')}",
                f"Issue: {finding.get('description', 'No description')}",
                f"Compliance: NIST {finding.get('nist_csf', 'N/A')} | SOC 2 {finding.get('soc2', 'N/A')}",
                f"Remediation: {finding.get('remediation', 'No remediation provided')[:150]}...",
                f""
            ])
    
    message_lines.extend([
        "",
        "=" * 70,
        "NEXT STEPS",
        "-" * 70,
        "1. Review all Critical findings and begin remediation immediately",
        "2. Schedule remediation tasks for High severity findings within 48 hours",
        "3. Verify fixes with a follow-up security assessment",
        "",
        "View full details in CloudWatch Dashboard:",
        f"https://console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name=AWS-Security-MCP-Dashboard",
        "",
        "This assessment was generated using AI-powered analysis with Amazon Bedrock Nova Pro.",
        "For questions or assistance, contact your security team.",
        ""
    ])
    
    message = "\n".join(message_lines)
    
    # Send SNS notification
    try:
        sns = boto3.client('sns', region_name=region)
        response = sns.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message,
            MessageStructure='string'
        )
        logger.info(f"Notification sent successfully. MessageId: {response['MessageId']}")
        logger.info(f"Bedrock-powered executive summary: {'Enabled' if use_bedrock else 'Disabled'}")
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        raise
