"""Vercel serverless entry point for Sentinel Cyber AI API.

Lightweight deployment for Vercel's serverless environment.
Heavy ML/AI dependencies (torch, transformers, etc.) run on AWS EC2.
"""
import sys
import os
import json
import logging

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Mark as Vercel environment so the app can skip heavy imports
os.environ["SENTINEL_PLATFORM"] = "vercel"
os.environ["SENTINEL_CORS_ORIGINS"] = os.environ.get("SENTINEL_CORS_ORIGINS", "*")
os.environ["SENTINEL_LOG_LEVEL"] = os.environ.get("SENTINEL_LOG_LEVEL", "INFO")

logging.basicConfig(level=getattr(logging, os.environ["SENTINEL_LOG_LEVEL"]))
logger = logging.getLogger("sentinel-vercel")

logger.info("🚀 Starting Sentinel Cyber AI on Vercel (lightweight mode)")

# Verify critical files exist
landing_page = os.path.join(project_root, "src", "api", "landing_page.html")
if os.path.exists(landing_page):
    logger.info(f"✅ landing_page.html found at {landing_page}")
else:
    logger.error(f"❌ landing_page.html NOT found at {landing_page}")
    # List what's available
    src_api = os.path.join(project_root, "src", "api")
    if os.path.exists(src_api):
        logger.info(f"Files in src/api/: {os.listdir(src_api)}")

try:
    from src.api.server import create_app
    app = create_app()
    logger.info("✅ Sentinel Cyber AI ready on Vercel")
except Exception as e:
    logger.error(f"❌ Failed to create app: {e}", exc_info=True)
    # Fallback: create a minimal app that returns error info
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    app = FastAPI(title="Sentinel Cyber AI (Vercel Error)")
    
    @app.get("/")
    @app.get("/{path:path}")
    async def error_route(path=""):
        return JSONResponse(
            status_code=500,
            content={
                "error": f"App creation failed: {str(e)}",
                "hint": "Check Vercel build logs for details"
            }
        )
    
    logger.warning("⚠️ Using fallback error app")
