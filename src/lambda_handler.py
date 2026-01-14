"""
Lambda handler wrapper for FastAPI MCP server
"""
from mangum import Mangum
from main import app

# Mangum adapter converts FastAPI to Lambda-compatible format
handler = Mangum(app, lifespan="off")
