"""Vercel serverless entry point for Sentinel Cyber AI API.

Exposes the FastAPI app as a Vercel serverless function.
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api.server import create_app

app = create_app()
