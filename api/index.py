"""Self-contained Vercel serverless entry point for Sentinel Cyber AI.

Lightweight standalone app — no dependency on src/ imports (avoids ML deps issues).
"""
import os
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel-vercel")

# ── Load landing page ──
_LANDING_PAGE = "<!DOCTYPE html><html><body><h1>Loading...</h1></body></html>"
_landing_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "api", "landing_page.html")
if os.path.exists(_landing_path):
    with open(_landing_path, "r", encoding="utf-8") as _f:
        _LANDING_PAGE = _f.read()
    logger.info("✅ Landing page loaded")
else:
    logger.warning(f"⚠️ Landing page not found at {_landing_path}")

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Counter, Histogram

# ── Metrics ──
METRIC_REQUESTS = Counter("http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
METRIC_LATENCY = Histogram("http_request_duration_seconds", "HTTP request duration", ["method", "endpoint"])

# ── Create App ──
app = FastAPI(
    title="Sentinel Cyber AI",
    description="Enterprise Multi-Agent Cybersecurity Platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware: metrics ──
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = time.time() - start
    METRIC_LATENCY.labels(method=request.method, endpoint=request.url.path).observe(elapsed)
    METRIC_REQUESTS.labels(method=request.method, endpoint=request.url.path, status=response.status_code).inc()
    response.headers["X-Process-Time-Ms"] = str(int(elapsed * 1000))
    return response

# ── Routes ──
@app.get("/", response_class=HTMLResponse)
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

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
