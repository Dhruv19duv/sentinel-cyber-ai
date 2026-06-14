"""Minimal Vercel deployment — Sentinel Cyber AI API."""
import os
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel-vercel")

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

# ── Load landing page ──
_LANDING_PAGE = "<!DOCTYPE html><html><body><h1>Sentinel Cyber AI</h1><p>Loading...</p></body></html>"
_landing_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "api", "landing_page.html"
)
if os.path.exists(_landing_path):
    with open(_landing_path, "r", encoding="utf-8") as _f:
        _LANDING_PAGE = _f.read()
    logger.info("✅ Landing page loaded")

# ── Create App ──
app = FastAPI(
    title="Sentinel Cyber AI",
    description="Enterprise Multi-Agent Cybersecurity Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return HTMLResponse(content=_LANDING_PAGE)

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "timestamp": time.time()}

@app.get("/api/info")
async def api_info():
    return {
        "name": "Sentinel Cyber AI",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
        "metrics": "/metrics",
        "timestamp": time.time(),
    }
