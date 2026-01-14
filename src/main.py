from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
import os
from typing import Dict, Any
import checks  # Changed from .checks
import mappings  # Changed from .mappings
import notifications  # Changed from .notifications

app = FastAPI(
    title="AWS Well-Architected Security MCP Server",
    description="MCP server for AWS Security Pillar assessments with NIST CSF & SOC 2 mappings",
    version="1.0.0"
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Get environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
ENABLE_BEDROCK = os.environ.get('ENABLE_BEDROCK', 'true').lower() == 'true'

class AssessRequest(BaseModel):
    region: str = "us-east-1"
    focus_areas: list[str] = ["IAM", "Logging", "Network"]
    send_notifications: bool = True

@app.get("/health")
async def health():
    """Health check endpoint for MCP clients."""
    return {
        "status": "healthy", 
        "service": "aws-well-architected-security-mcp",
        "bedrock_enabled": ENABLE_BEDROCK
    }

@app.post("/assess")
async def assess(request: AssessRequest):
    """Run a full security assessment using the MCP tools."""
    try:
        # Collect raw findings from AWS
        raw_findings = checks.collect_security_findings(request.region, request.focus_areas)
        
        # Apply compliance mappings
        enriched_findings = mappings.map_to_nist_soc2(raw_findings)
        
        # Send notifications for critical findings if enabled
        if request.send_notifications and SNS_TOPIC_ARN:
            try:
                notifications.send_critical_findings_notification(
                    enriched_findings, 
                    SNS_TOPIC_ARN, 
                    request.region,
                    use_bedrock=ENABLE_BEDROCK
                )
            except Exception as e:
                logger.warning(f"Notification failed but assessment succeeded: {str(e)}")
        
        # Count findings by severity
        critical_count = len([f for f in enriched_findings if f.get('severity', '').lower() == 'critical'])
        high_count = len([f for f in enriched_findings if f.get('severity', '').lower() == 'high'])
        
        return {
            "status": "success",
            "assessment": {
                "region": request.region,
                "focus_areas": request.focus_areas,
                "findings": enriched_findings,
                "critical_count": critical_count,
                "high_count": high_count,
                "notifications_sent": request.send_notifications and bool(SNS_TOPIC_ARN),
                "bedrock_enabled": ENABLE_BEDROCK,
                "timestamp": "2026-01-13T16:37:00Z"
            }
        }
    except Exception as e:
        logger.error(f"Assessment failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))