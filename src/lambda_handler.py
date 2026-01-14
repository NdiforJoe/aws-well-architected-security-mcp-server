"""
Lambda handler wrapper for FastAPI MCP server
"""
from mangum import Mangum
import main

# Mangum adapter converts FastAPI to Lambda-compatible format
handler = Mangum(main.app, lifespan="off")