"""API Server — Enterprise-grade REST API for Sentinel Cyber AI.

FastAPI-based server with:
- Authentication (API key)
- Rate limiting
- CORS support
- Request/response logging
- Health checks
- Prometheus metrics
- Sentry error tracking (opt-in via SENTRY_DSN env var)
"""

import logging
import time
import os
import sys
from contextlib import asynccontextmanager
from typing import Optional

import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, Response, HTMLResponse

# ── Prometheus Metrics ──
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

METRIC_REQUESTS = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
METRIC_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
METRIC_ACTIVE_REQUESTS = Gauge(
    "http_active_requests",
    "Number of active HTTP requests",
)
# WebSocket connections are tracked by the dashboard server, not the API server
METRIC_ANALYSES = Counter(
    "sentinel_analyses_total",
    "Total security analyses performed",
    ["status"],
)
METRIC_FINDINGS_CRITICAL = Gauge(
    "sentinel_critical_findings_total",
    "Current count of critical findings in the last scan",
)
METRIC_FINDINGS_HIGH = Gauge(
    "sentinel_high_findings_total",
    "Current count of high-severity findings in the last scan",
)
METRIC_FINDINGS_MEDIUM = Gauge(
    "sentinel_medium_findings_total",
    "Current count of medium-severity findings in the last scan",
)

logger = logging.getLogger(__name__)


# ── Landing Page HTML (loaded from external file) ──
_landing_page_path = os.path.join(os.path.dirname(__file__), "landing_page.html")
with open(_landing_page_path, "r", encoding="utf-8") as _f:
    _LANDING_PAGE = _f.read()


# ── Sentry Initialization ──
def init_sentry():
    """Initialize Sentry SDK if SENTRY_DSN is configured."""
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        logger.info("Sentry disabled — set SENTRY_DSN to enable error tracking")
        return False

    environment = os.environ.get("SENTINEL_ENV", "production")
    release = os.environ.get("SENTINEL_VERSION", "latest")

    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        release=release,
        integrations=[
            FastApiIntegration(),
            LoggingIntegration(level=logging.INFO, event_level=logging.WARNING),
        ],
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.5")),
        profiles_sample_rate=float(os.environ.get("SENTRY_PROFILES_SAMPLE_RATE", "0.1")),
        send_default_pii=False,
        max_breadcrumbs=50,
        attach_stacktrace=True,
    )

    logger.info(f"Sentry initialized (env={environment}, release={release})")
    return True

# Security scheme
security = HTTPBearer(auto_error=False)


def verify_api_key(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Verify API key from Authorization header."""
    api_key = os.environ.get("SENTINEL_API_KEY")
    if not api_key:
        # No API key configured — allow all requests
        return True

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if credentials.credentials != api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — initialize and cleanup."""
    # Startup
    logger.info("🚀 Sentinel Cyber AI API starting...")
    from src.main import setup_orchestrator
    app.state.orchestrator = setup_orchestrator()

    # Import and setup routes
    from src.api.routes import setup_routes
    app.include_router(setup_routes(app.state.orchestrator))

    # Setup integration admin routes
    from src.api.integration_routes import setup_integration_routes
    app.include_router(setup_integration_routes(app.state.orchestrator))

    # Setup Slack webhook routes
    from src.integrations.slack_bot import setup_slack_routes
    from fastapi import APIRouter
    slack_router = APIRouter()
    app.include_router(setup_slack_routes(slack_router, app.state.orchestrator))

    # Setup Discord interaction routes
    from src.integrations.discord_bot import setup_discord_routes
    discord_router = APIRouter()
    app.include_router(setup_discord_routes(discord_router, app.state.orchestrator))

    # Setup GitHub webhook routes
    from src.integrations.github_webhook import setup_github_routes
    gh_router = APIRouter()
    mon = getattr(app.state.orchestrator, 'monitoring', None)
    app.include_router(setup_github_routes(gh_router, app.state.orchestrator, mon))

    # Setup SIEM routes
    from src.integrations.siem import SIEMForwarder
    app.state.siem = SIEMForwarder()

    # Setup Auto-Remediation routes
    from src.integrations.auto_remediation import AutoRemediationEngine
    app.state.remediation = AutoRemediationEngine(app.state.orchestrator)

    logger.info("Sentinel API ready")
    yield

    # Shutdown
    logger.info("Sentinel API shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Initialize Sentry before app creation (catches startup errors too)
    init_sentry()

    app = FastAPI(
        title="Sentinel Cyber AI",
        description="Enterprise Multi-Agent Cybersecurity Platform",
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get(
            "SENTINEL_CORS_ORIGINS", "*"
        ).split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware: Prometheus metrics + request timing
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        METRIC_ACTIVE_REQUESTS.inc()
        start = time.time()
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            elapsed = time.time() - start
            METRIC_LATENCY.labels(method=request.method, endpoint=request.url.path).observe(elapsed)
            METRIC_ACTIVE_REQUESTS.dec()
            status_code = response.status_code if response is not None else 500
            METRIC_REQUESTS.labels(
                method=request.method,
                endpoint=request.url.path,
                status=status_code,
            ).inc()
            if response is not None:
                response.headers["X-Process-Time-Ms"] = str(int(elapsed * 1000))

    # Middleware: Error handling with Sentry
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        sentry_sdk.capture_exception(exc)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(exc) if os.environ.get("SENTINEL_DEBUG") else "An unexpected error occurred"},
        )

    # Root endpoint — Epic Landing Page (loaded from external file)
    @app.get("/", response_class=HTMLResponse)
    async def root():
        return HTMLResponse(content=_LANDING_PAGE)

    # Root JSON API info (for programmatic access)
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

    # Health check endpoint (no auth required)
    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "version": "2.0.0",
            "timestamp": time.time(),
        }

    # Prometheus metrics endpoint (no auth required for Prometheus scraping)
    @app.get("/metrics")
    async def metrics():
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


def serve(host: str = "0.0.0.0", port: int = 8080):
    """Start the API server."""
    import uvicorn
    print(f"\n{'='*60}")
    print(f"🔐 Sentinel Cyber AI API Server")
    print(f"{'='*60}")
    print(f"Docs:       http://localhost:{port}/docs")
    print(f"Health:     http://localhost:{port}/health")
    print(f"API v1:     http://localhost:{port}/api/v1/analyze")
    print(f"{'='*60}\n")

    uvicorn.run(
        "src.api.server:create_app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    serve()
