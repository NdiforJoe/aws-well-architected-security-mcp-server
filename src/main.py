from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
from typing import Dict, Any

from .checks import collect_security_findings
from .mappings import map_to_nist_soc2

app = FastAPI(
    title="AWS Well-Architected Security MCP Server",
    description="MCP server for AWS Security Pillar assessments with NIST CSF & SOC 2 mappings",
    version="1.0.0"
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class AssessRequest(BaseModel):
    region: str = "us-east-1"
    focus_areas: list[str] = ["IAM", "Logging", "Network"]

@app.get("/health")
async def health():
    """Health check endpoint for MCP clients."""
    return {"status": "healthy", "service": "aws-well-architected-security-mcp"}

@app.post("/assess")
async def assess(request: AssessRequest):
    """Run a full security assessment using the MCP tools."""
    try:
        # Collect raw findings from AWS
        raw_findings = collect_security_findings(request.region, request.focus_areas)
        
        # Apply compliance mappings
        enriched_findings = map_to_nist_soc2(raw_findings)
        
        return {
            "status": "success",
            "assessment": {
                "region": request.region,
                "focus_areas": request.focus_areas,
                "findings": enriched_findings,
                "timestamp": "2026-01-13T16:37:00Z"
            }
        }
    except Exception as e:
        logger.error(f"Assessment failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))