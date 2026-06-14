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

# app must be defined at module level for Vercel to detect it
app = None

try:
    from src.api.server import create_app
    app = create_app()
    logger.info("✅ Sentinel Cyber AI ready on Vercel")
except Exception as e:
    logger.error(f"❌ Failed to create app: {e}", exc_info=True)

if app is None:
    # Fallback: create a minimal debug app
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, HTMLResponse
    
    fallback_app = FastAPI(title="Sentinel Cyber AI (Vercel Error)")
    
    @fallback_app.get("/")
    @fallback_app.get("/{path:path}")
    async def error_route(path: str = ""):
        return JSONResponse(
            status_code=500,
            content={
                "error": "App creation failed",
                "detail": str(e) if 'e' in dir() else "Unknown error",
                "hint": "Check Vercel build logs for details"
            }
        )
    
    app = fallback_app
    logger.warning("⚠️ Using fallback error app")
