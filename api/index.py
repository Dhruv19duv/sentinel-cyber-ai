"""Vercel serverless entry point for Sentinel Cyber AI API.

Lightweight deployment for Vercel's serverless environment.
Heavy ML/AI dependencies (torch, transformers, etc.) run on AWS EC2.
"""
import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mark as Vercel environment so the app can skip heavy imports
os.environ["SENTINEL_PLATFORM"] = "vercel"
os.environ["SENTINEL_CORS_ORIGINS"] = os.environ.get("SENTINEL_CORS_ORIGINS", "*")
os.environ["SENTINEL_LOG_LEVEL"] = os.environ.get("SENTINEL_LOG_LEVEL", "INFO")

logging.basicConfig(level=getattr(logging, os.environ["SENTINEL_LOG_LEVEL"]))
logger = logging.getLogger("sentinel-vercel")

logger.info("🚀 Starting Sentinel Cyber AI on Vercel (lightweight mode)")

from src.api.server import create_app

app = create_app()

logger.info("✅ Sentinel Cyber AI ready on Vercel")
