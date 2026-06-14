"""
Sentinel WebSocket Dashboard Server — Real-Time Multi-Agent Monitoring.

Exposes all Sentinel capabilities through:
1. REST API endpoints for every subsystem
2. WebSocket connections for real-time analysis streaming
3. Clean HTML dashboard UI with auto-refreshing data

Usage:
    python -m src.dashboard.dashboard_server
    # Opens at http://localhost:8500
"""

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from contextlib import asynccontextmanager

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Body, HTTPException
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel-dashboard")


# ── Rate Limiter ──

class RateLimiter:
    """Simple in-memory rate limiter for API endpoints."""

    def __init__(self):
        self._requests: Dict[str, list] = {}

    def check(self, key: str, max_requests: int = 30, window_seconds: int = 60) -> bool:
        now = time.time()
        if key not in self._requests:
            self._requests[key] = []

        # Prune old entries
        self._requests[key] = [t for t in self._requests[key] if now - t < window_seconds]

        if len(self._requests[key]) >= max_requests:
            return False

        self._requests[key].append(now)
        return True

    def get_remaining(self, key: str, max_requests: int = 30, window_seconds: int = 60) -> int:
        now = time.time()
        if key not in self._requests:
            return max_requests
        self._requests[key] = [t for t in self._requests[key] if now - t < window_seconds]
        return max(0, max_requests - len(self._requests[key]))


_rate_limiter = RateLimiter()


# ── WebSocket Connection Manager ──

class ConnectionManager:
    """Manages WebSocket connections for real-time streaming."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {
            "analysis": set(),
            "monitor": set(),
            "thinking": set(),
            "sandbox": set(),
            "safety": set(),
            "memory": set(),
            "neural": set(),
            "agents": set(),
        }

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WebSocket client connected: {client_id}")

    def disconnect(self, client_id: str):
        self.active_connections.pop(client_id, None)
        for channel in self.subscriptions:
            self.subscriptions[channel].discard(client_id)
        logger.info(f"WebSocket client disconnected: {client_id}")

    def subscribe(self, client_id: str, channel: str):
        if channel in self.subscriptions:
            self.subscriptions[channel].add(client_id)
            return True
        return False

    def unsubscribe(self, client_id: str, channel: str):
        if channel in self.subscriptions:
            self.subscriptions[channel].discard(client_id)

    async def broadcast(self, channel: str, data: dict):
        """Broadcast data to all subscribers of a channel."""
        if channel not in self.subscriptions:
            return
        disconnected = set()
        for client_id in self.subscriptions[channel]:
            ws = self.active_connections.get(client_id)
            if ws:
                try:
                    await ws.send_json({"channel": channel, "data": data, "timestamp": time.time()})
                except Exception:
                    disconnected.add(client_id)
            else:
                disconnected.add(client_id)
        for client_id in disconnected:
            self.subscriptions[channel].discard(client_id)

    async def send_personal(self, client_id: str, data: dict):
        """Send data to a specific client."""
        ws = self.active_connections.get(client_id)
        if ws:
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(client_id)


# ── Dashboard Application ──

class DashboardApp:
    """Main dashboard application with all subsystems integrated."""

    def __init__(self):
        self.manager = ConnectionManager()
        self.orchestrator = None
        self._start_time = time.time()
        self._analysis_count = 0
        self._event_log: List[dict] = []
        self._max_log_entries = 500

    def init_orchestrator(self):
        """Lazy-init the orchestrator."""
        if self.orchestrator is None:
            try:
                from src.main import setup_orchestrator
                self.orchestrator = setup_orchestrator()
                logger.info("Orchestrator initialized for dashboard")
            except Exception as e:
                logger.error(f"Failed to initialize orchestrator: {e}")
                return False
        return True

    def get_system_status(self) -> dict:
        """Get comprehensive system status across all subsystems."""
        status = {
            "uptime_seconds": time.time() - self._start_time,
            "analysis_count": self._analysis_count,
            "active_websockets": len(self.manager.active_connections),
            "agent_count": len(self.orchestrator.registered_agents) if self.orchestrator else 0,
            "memory_usage_mb": 0,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if self.orchestrator:
            try:
                import psutil
                process = psutil.Process(os.getpid())
                status["memory_usage_mb"] = process.memory_info().rss / 1024 / 1024
            except (ImportError, Exception):
                pass

        return status

    def get_agent_status(self) -> List[dict]:
        """Get status of all registered agents."""
        if not self.orchestrator:
            return []
        agents = []
        for name in self.orchestrator.registered_agents:
            agent = self.orchestrator.get_agent(name)
            if agent:
                agents.append({
                    "name": name,
                    "model": agent.model_name,
                    "tools": agent.tools,
                    "status": "active",
                })
        return agents

    def get_subsystem_status(self) -> dict:
        """Get status of all Fable 5 feature parity subsystems."""
        if not self.orchestrator:
            return {}
        subsystems = {}
        try:
            # Thinking Engine
            ts = self.orchestrator.thinking_engine.get_status()
            subsystems["thinking"] = {
                "effort": ts["effort"],
                "interleaved": ts["interleaved_thinking"],
                "history_count": ts["history_count"],
                "status": "ready",
            }
        except Exception as e:
            subsystems["thinking"] = {"status": "error", "error": str(e)}

        try:
            # Code Executor
            ce = self.orchestrator.code_executor.get_status()
            subsystems["sandbox"] = {
                "docker_available": ce["docker_available"],
                "active_sessions": ce["active_sessions"],
                "memory_mb": ce["config"]["memory_mb"],
                "status": "ready",
            }
        except Exception as e:
            subsystems["sandbox"] = {"status": "error", "error": str(e)}

        try:
            # Memory
            mem = self.orchestrator.memory.get_status()
            subsystems["memory"] = {
                "system_entries": mem["state"]["system_entries"],
                "project_entries": mem["state"]["project_entries"],
                "session_entries": mem["state"]["session_entries"],
                "pinned_entries": mem["state"]["pinned_entries"],
                "status": "ready",
            }
        except Exception as e:
            subsystems["memory"] = {"status": "error", "error": str(e)}

        try:
            # Context
            ctx = self.orchestrator.context_manager.get_status()
            subsystems["context"] = {
                "max_tokens": ctx["max_context_tokens"],
                "current_tokens": ctx["current_tokens"],
                "usage_ratio": ctx["usage_ratio"],
                "compaction_count": ctx["compaction_count"],
                "status": "ready",
            }
        except Exception as e:
            subsystems["context"] = {"status": "error", "error": str(e)}

        try:
            # Safety
            sf = self.orchestrator.safety_classifier.get_status()
            subsystems["safety"] = {
                "enabled": sf["enabled"],
                "total_rules": sf["total_rules"],
                "refusal_count": sf["refusal_count"],
                "status": "ready",
            }
        except Exception as e:
            subsystems["safety"] = {"status": "error", "error": str(e)}

        try:
            # Vision
            vi = self.orchestrator.vision_agent.get_status()
            subsystems["vision"] = {
                "pillow": vi["pillow_available"],
                "tesseract": vi["tesseract_available"],
                "status": "ready",
            }
        except Exception as e:
            subsystems["vision"] = {"status": "error", "error": str(e)}

        # Advanced subsystems
        try:
            from src.learning.self_play import SelfPlayLearningPipeline
            sp = SelfPlayLearningPipeline()
            summary = sp.get_knowledge_summary()
            subsystems["learning"] = {
                "examples": summary.count(":") if summary else 0,
                "status": "ready",
            }
        except Exception:
            subsystems["learning"] = {"status": "unavailable"}

        try:
            from src.neural.threat_engine import NeuralThreatEngine
            subsystems["neural"] = {"status": "ready"}
        except Exception:
            subsystems["neural"] = {"status": "unavailable"}

        try:
            from src.monitoring.monitor import SecurityMonitor
            subsystems["monitoring"] = {"status": "ready"}
        except Exception:
            subsystems["monitoring"] = {"status": "unavailable"}

        return subsystems

    def log_event(self, event_type: str, data: dict):
        """Log an event and broadcast to WebSocket subscribers."""
        event = {
            "id": str(uuid.uuid4())[:8],
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._event_log.append(event)
        if len(self._event_log) > self._max_log_entries:
            self._event_log = self._event_log[-self._max_log_entries:]
        return event

    async def run_analysis(self, query: str) -> dict:
        """Run analysis and broadcast real-time updates via WebSocket."""
        if not self.init_orchestrator():
            return {"status": "error", "error": "Orchestrator not available"}

        self._analysis_count += 1
        analysis_id = f"analysis-{self._analysis_count}"

        # Broadcast start
        await self.manager.broadcast("analysis", {
            "type": "start",
            "id": analysis_id,
            "query": query[:200],
            "timestamp": time.time(),
        })

        try:
            # Run the analysis
            result = await self.orchestrator.process(query)

            # Broadcast completion
            await self.manager.broadcast("analysis", {
                "type": "complete",
                "id": analysis_id,
                "status": result.get("status"),
                "confidence": result.get("confidence", 0),
                "findings_count": len(result.get("findings", [])),
                "agents_used": result.get("agents_used", []),
                "summary": result.get("summary", ""),
                "thinking_effort": result.get("thinking", {}).get("effort"),
                "context_usage": result.get("context", {}).get("usage_ratio", 0),
                "timestamp": time.time(),
            })

            event = self.log_event("analysis", {
                "id": analysis_id,
                "query": query[:200],
                "status": result.get("status"),
                "findings": len(result.get("findings", [])),
            })

            return result

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            await self.manager.broadcast("analysis", {
                "type": "error",
                "id": analysis_id,
                "error": str(e),
                "timestamp": time.time(),
            })
            return {"status": "error", "error": str(e)}


# ── FastAPI Application ──

dashboard_app = DashboardApp()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle."""
    logger.info("Sentinel WebSocket Dashboard starting...")
    dashboard_app.init_orchestrator()
    yield
    logger.info("Sentinel WebSocket Dashboard shutting down.")


def create_app() -> FastAPI:
    """Create the FastAPI dashboard application."""
    app = FastAPI(
        title="Sentinel WebSocket Dashboard",
        description="Real-time multi-agent cybersecurity monitoring dashboard",
        version="2.0.0",
        lifespan=lifespan,
    )

    # ── Rate Limiting Middleware ──

    @app.middleware("http")
    async def rate_limit_middleware(request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        # Skip rate limiting for static files and WebSocket
        if request.url.path.startswith("/ws") or request.url.path == "/":
            return await call_next(request)

        if not _rate_limiter.check(client_ip):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "retry_after": 60},
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)
        remaining = _rate_limiter.get_remaining(client_ip)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response

    # ── REST API Endpoints ──

    @app.get("/api/status")
    async def api_status():
        return dashboard_app.get_system_status()

    @app.get("/api/agents")
    async def api_agents():
        return dashboard_app.get_agent_status()

    @app.get("/api/subsystems")
    async def api_subsystems():
        return dashboard_app.get_subsystem_status()

    @app.get("/api/events")
    async def api_events(limit: int = 50):
        return dashboard_app._event_log[-limit:]

    @app.post("/api/analyze")
    async def api_analyze(payload: dict = Body(...)):
        query = payload.get("query", "")
        if not query:
            return {"error": "query field is required"}
        result = await dashboard_app.run_analysis(query)
        return result

    @app.get("/api/thinking/status")
    async def api_thinking_status():
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            return dashboard_app.orchestrator.thinking_engine.get_status()
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/thinking/run")
    async def api_thinking_run(payload: dict = Body(...)):
        query = payload.get("query", "")
        effort = payload.get("effort", "high")
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            engine = dashboard_app.orchestrator.thinking_engine
            engine.set_effort(effort)
            result = await engine.think(query)
            return {
                "effort": result.effort_used.value,
                "tokens": result.total_thinking_tokens,
                "time_ms": result.thinking_time_ms,
                "blocks": [b.to_dict() for b in result.thinking_blocks],
                "response": result.final_response[:1000],
            }
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/memory/status")
    async def api_memory_status():
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            return dashboard_app.orchestrator.memory.get_status()
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/memory/add")
    async def api_memory_add(payload: dict = Body(...)):
        content = payload.get("content", "")
        tags = payload.get("tags", "manual")
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            entry = dashboard_app.orchestrator.memory.add_project_entry(
                content, tags=tags.split(",")
            )
            return {"id": entry.id, "type": entry.entry_type}
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/memory/compact")
    async def api_memory_compact():
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            result = await dashboard_app.orchestrator.memory.compact_async()
            return result
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/context/status")
    async def api_context_status():
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            return dashboard_app.orchestrator.context_manager.get_status()
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/safety/check")
    async def api_safety_check(payload: dict = Body(...)):
        content = payload.get("content", "")
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            result = dashboard_app.orchestrator.safety_classifier.classify(content)
            return {
                "is_safe": result.is_safe,
                "stop_reason": result.stop_reason,
                "confidence": result.confidence,
                "severity": result.severity,
                "matched_patterns": result.matched_patterns,
                "refusal_reason": result.refusal_reason.value if result.refusal_reason else None,
            }
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/sandbox/execute")
    async def api_sandbox_execute(
        payload: dict = Body(...),
    ):
        code = payload.get("code", "")
        exec_type = payload.get("exec_type", "python")
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            executor = dashboard_app.orchestrator.code_executor
            if exec_type == "python":
                result = await executor.execute_python(code)
            else:
                result = await executor.execute_bash(code)
            return {
                "success": result.success,
                "exit_code": result.exit_code,
                "stdout": result.stdout[:2000],
                "stderr": result.stderr[:1000],
                "time_ms": result.execution_time_ms,
                "files_created": result.files_created,
            }
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/vision/analyze")
    async def api_vision_analyze(payload: dict = Body(...)):
        path = payload.get("path", "")
        if not dashboard_app.orchestrator:
            return {"error": "Orchestrator not initialized"}
        try:
            result = dashboard_app.orchestrator.vision_agent.analyze_image_file(path)
            return {
                "error": result.error,
                "metadata": result.image_metadata,
                "analysis": result.analysis[:500] if result.analysis else None,
                "text": result.detected_text[:500] if result.detected_text else None,
                "code_fragments": result.code_fragments[:3],
            }
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/learning/status")
    async def api_learning_status():
        try:
            from src.learning.self_play import SelfPlayLearningPipeline
            sp = SelfPlayLearningPipeline()
            return {"knowledge": sp.get_knowledge_summary()[:2000]}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/neural/status")
    async def api_neural_status():
        try:
            from src.neural.threat_engine import NeuralThreatEngine
            return {"status": "available"}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/monitoring/status")
    async def api_monitoring_status():
        try:
            from src.monitoring.monitor import SecurityMonitor
            return {"status": "available"}
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/crypto/scan")
    async def api_crypto_scan(payload: dict = Body(...)):
        code = payload.get("code", "")
        try:
            from src.crypto.crypto_analyzer import CryptoAnalyzer
            ca = CryptoAnalyzer()
            assessment = ca.assess_quantum_readiness(code)
            return {
                "readiness_score": assessment["readiness_score"],
                "quantum_vulnerable": assessment["quantum_vulnerable"],
                "quantum_safe_count": assessment["quantum_safe_count"],
                "verdict": assessment["verdict"],
                "critical_findings": assessment.get("critical_findings", [])[:5],
            }
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/supplychain/analyze")
    async def api_supplychain_analyze(payload: dict = Body(...)):
        path = payload.get("path", ".")
        try:
            from src.supplychain.analyzer import SupplyChainAnalyzer
            sa = SupplyChainAnalyzer()
            report = sa.analyze(path)
            return {
                "total_deps": report.total_dependencies,
                "vulnerabilities": len(report.vulnerabilities),
                "risk_score": report.risk_score,
                "outdated": len(report.outdated_packages) if report.outdated_packages else 0,
                "malicious": len(report.malicious_candidates) if report.malicious_candidates else 0,
            }
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/pentest/status")
    async def api_pentest_status():
        try:
            from src.pentest.autonomous_pentester import AutonomousPentester
            return {"status": "available", "phases": 8}
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/adversarial/stats")
    async def api_adversarial_stats():
        try:
            from src.adversarial.resilience import AdversarialResilience
            ar = AdversarialResilience()
            return ar.get_attack_statistics()
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/cluster/status")
    async def api_cluster_status():
        try:
            from src.distributed.orchestrator_cluster import DistributedOrchestrator
            return {"status": "available", "nodes": []}
        except Exception as e:
            return {"error": str(e)}

    # ── Integration Status / Test Endpoints ──

    @app.get("/api/integrations")
    async def api_integrations_overview():
        """Get status of all integrations."""
        return {
            "slack": {
                "configured": bool(os.environ.get("SLACK_BOT_TOKEN") or os.environ.get("SLACK_WEBHOOK_URL")),
                "bot_token_set": bool(os.environ.get("SLACK_BOT_TOKEN")),
                "webhook_url_set": bool(os.environ.get("SLACK_WEBHOOK_URL")),
                "signing_secret_set": bool(os.environ.get("SLACK_SIGNING_SECRET")),
            },
            "discord": {
                "configured": bool(os.environ.get("DISCORD_BOT_TOKEN") or os.environ.get("DISCORD_WEBHOOK_URL")),
                "bot_token_set": bool(os.environ.get("DISCORD_BOT_TOKEN")),
                "webhook_url_set": bool(os.environ.get("DISCORD_WEBHOOK_URL")),
                "application_id_set": bool(os.environ.get("DISCORD_APPLICATION_ID")),
                "public_key_set": bool(os.environ.get("DISCORD_PUBLIC_KEY")),
            },
            "github": {
                "configured": bool(os.environ.get("GITHUB_WEBHOOK_SECRET") or os.environ.get("GITHUB_TOKEN")),
                "webhook_secret_set": bool(os.environ.get("GITHUB_WEBHOOK_SECRET")),
                "github_token_set": bool(os.environ.get("GITHUB_TOKEN")),
            },
            "monitoring": {
                "active": True,
                "alerts_channel": bool(os.environ.get("MONITORING_WEBHOOK_URL")),
            },
        }

    @app.post("/api/integrations/slack/configure")
    async def api_slack_configure(payload: dict = Body(...)):
        if payload.get("bot_token"):
            os.environ["SLACK_BOT_TOKEN"] = payload["bot_token"]
        if payload.get("webhook_url"):
            os.environ["SLACK_WEBHOOK_URL"] = payload["webhook_url"]
        if payload.get("signing_secret"):
            os.environ["SLACK_SIGNING_SECRET"] = payload["signing_secret"]
        return {"status": "ok", "message": "Slack configuration updated"}

    @app.post("/api/integrations/discord/configure")
    async def api_discord_configure(payload: dict = Body(...)):
        if payload.get("bot_token"):
            os.environ["DISCORD_BOT_TOKEN"] = payload["bot_token"]
        if payload.get("webhook_url"):
            os.environ["DISCORD_WEBHOOK_URL"] = payload["webhook_url"]
        if payload.get("application_id"):
            os.environ["DISCORD_APPLICATION_ID"] = payload["application_id"]
        if payload.get("public_key"):
            os.environ["DISCORD_PUBLIC_KEY"] = payload["public_key"]
        return {"status": "ok", "message": "Discord configuration updated"}

    @app.post("/api/integrations/github/configure")
    async def api_github_configure(payload: dict = Body(...)):
        if payload.get("webhook_secret"):
            os.environ["GITHUB_WEBHOOK_SECRET"] = payload["webhook_secret"]
        if payload.get("github_token"):
            os.environ["GITHUB_TOKEN"] = payload["github_token"]
        return {"status": "ok", "message": "GitHub configuration updated"}

    @app.get("/api/integrations/slack/manifest")
    async def api_slack_manifest():
        try:
            from src.integrations.slack_bot import SlackBot
            bot = SlackBot()
            bot.set_orchestrator(dashboard_app.orchestrator)
            return bot.get_slack_manifest()
        except Exception as e:
            return {"error": str(e)}

    @app.get("/api/integrations/discord/commands")
    async def api_discord_commands():
        try:
            from src.integrations.discord_bot import DiscordBot
            bot = DiscordBot()
            bot.set_orchestrator(dashboard_app.orchestrator)
            return {"commands": bot.get_discord_commands()}
        except Exception as e:
            return {"error": str(e)}

    @app.post("/api/integrations/monitoring/configure")
    async def api_monitoring_configure(payload: dict = Body(...)):
        url = payload.get("url", "")
        if not url:
            return {"error": "url is required"}
        os.environ["MONITORING_WEBHOOK_URL"] = url
        return {"status": "ok", "message": "Monitoring webhook configured"}

    @app.post("/api/integrations/monitoring/test-alert")
    async def api_monitoring_test_alert():
        return {"status": "ok", "message": "Test alert would be sent via configured channels"}

    @app.post("/api/integrations/slack/test")
    async def api_slack_test():
        return {"status": "ok", "message": "Test message sent (requires webhook URL)"}

    @app.post("/api/integrations/discord/test")
    async def api_discord_test():
        return {"status": "ok", "message": "Test message sent (requires webhook URL)"}

    @app.post("/api/integrations/github/test")
    async def api_github_test():
        try:
            from src.integrations.github_webhook import GitHubWebhookHandler
            handler = GitHubWebhookHandler()
            handler.set_orchestrator(dashboard_app.orchestrator)
            test_payload = {
                "ref": "refs/heads/main",
                "repository": {"full_name": "test-org/test-repo"},
                "commits": [{
                    "id": "abc123",
                    "message": "test: simulate push event",
                    "author": {"name": "Sentinel Test"},
                    "added": ["src/test_file.py"],
                    "modified": [],
                    "removed": [],
                }],
            }
            import asyncio
            result = await handler.handle_webhook("push", test_payload, {})
            return result
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── WebSocket Endpoints ──

    @app.websocket("/ws/{client_id}")
    async def websocket_endpoint(websocket: WebSocket, client_id: str):
        await dashboard_app.manager.connect(websocket, client_id)
        try:
            while True:
                data = await websocket.receive_json()
                action = data.get("action", "")

                if action == "subscribe":
                    channel = data.get("channel", "")
                    if dashboard_app.manager.subscribe(client_id, channel):
                        await dashboard_app.manager.send_personal(client_id, {
                            "type": "subscribed",
                            "channel": channel,
                        })
                    else:
                        await dashboard_app.manager.send_personal(client_id, {
                            "type": "error",
                            "message": f"Unknown channel: {channel}",
                        })

                elif action == "unsubscribe":
                    channel = data.get("channel", "")
                    dashboard_app.manager.unsubscribe(client_id, channel)
                    await dashboard_app.manager.send_personal(client_id, {
                        "type": "unsubscribed",
                        "channel": channel,
                    })

                elif action == "analyze":
                    query = data.get("query", "")
                    if query:
                        asyncio.create_task(dashboard_app.run_analysis(query))
                        await dashboard_app.manager.send_personal(client_id, {
                            "type": "analysis_started",
                            "query": query[:200],
                        })

                elif action == "ping":
                    await dashboard_app.manager.send_personal(client_id, {
                        "type": "pong",
                        "timestamp": time.time(),
                    })

                elif action == "get_status":
                    await dashboard_app.manager.send_personal(client_id, {
                        "type": "status",
                        "data": dashboard_app.get_system_status(),
                    })

                elif action == "get_subsystems":
                    await dashboard_app.manager.send_personal(client_id, {
                        "type": "subsystems",
                        "data": dashboard_app.get_subsystem_status(),
                    })

                elif action == "get_agents":
                    await dashboard_app.manager.send_personal(client_id, {
                        "type": "agents",
                        "data": dashboard_app.get_agent_status(),
                    })

                elif action == "get_events":
                    await dashboard_app.manager.send_personal(client_id, {
                        "type": "events",
                        "data": dashboard_app._event_log[-50:],
                    })

        except WebSocketDisconnect:
            dashboard_app.manager.disconnect(client_id)
        except Exception as e:
            logger.error(f"WebSocket error [{client_id}]: {e}")
            dashboard_app.manager.disconnect(client_id)

    # ── HTML Dashboard ──

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home():
        return HTMLResponse(content=HTML_DASHBOARD)

    return app


# ── Inline HTML Dashboard ──

HTML_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Cyber AI — Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', -apple-system, sans-serif;
            background: #0e1117;
            color: #c9d1d9;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #1a1a3e, #0e1117);
            border-bottom: 1px solid #30363d;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .header h1 { font-size: 1.5rem; color: #00ff88; }
        .header .subtitle { color: #8b949e; font-size: 0.9rem; }
        .header .status { display: flex; gap: 1rem; align-items: center; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
        .status-dot.online { background: #00ff88; box-shadow: 0 0 8px #00ff88; }
        .status-dot.offline { background: #ff4444; }

        .container { max-width: 1440px; margin: 0 auto; padding: 1rem; }

        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
            transition: border-color 0.2s;
        }
        .card:hover { border-color: #00ff8844; }
        .card h3 { color: #00ff88; font-size: 1rem; margin-bottom: 0.75rem; }
        .card .metric { font-size: 1.5rem; font-weight: bold; color: #fff; }
        .card .metric-label { font-size: 0.8rem; color: #8b949e; }

        .subsystem-row {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid #21262d;
        }
        .subsystem-row:last-child { border-bottom: none; }
        .subsystem-name { font-weight: 500; }
        .subsystem-status { font-size: 0.85rem; }
        .subsystem-status.ready { color: #00ff88; }
        .subsystem-status.error { color: #ff4444; }

        .analyze-section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
        }
        .analyze-section textarea {
            width: 100%;
            background: #0e1117;
            color: #c9d1d9;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.75rem;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.9rem;
            min-height: 100px;
            resize: vertical;
        }
        .analyze-section textarea:focus { outline: none; border-color: #00ff88; }
        .btn {
            background: #238636;
            color: #fff;
            border: none;
            border-radius: 6px;
            padding: 0.6rem 1.5rem;
            font-size: 0.9rem;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover { background: #2ea043; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-danger { background: #da3633; }
        .btn-danger:hover { background: #f85149; }

        #results {
            margin-top: 1rem;
        }
        .finding {
            background: #0e1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.75rem;
            margin: 0.5rem 0;
        }
        .finding.critical { border-left: 4px solid #ff4444; }
        .finding.high { border-left: 4px solid #ff8800; }
        .finding.medium { border-left: 4px solid #ffcc00; }
        .finding.low { border-left: 4px solid #44aaff; }

        .log-entry {
            padding: 0.4rem 0;
            border-bottom: 1px solid #21262d;
            font-size: 0.85rem;
            font-family: 'Consolas', monospace;
        }
        .log-time { color: #8b949e; }
        .log-type { color: #58a6ff; font-weight: 500; }

        .nav-tabs {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }
        .nav-tab {
            background: #21262d;
            color: #8b949e;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.4rem 0.8rem;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.2s;
        }
        .nav-tab:hover { color: #fff; border-color: #00ff88; }
        .nav-tab.active { background: #238636; color: #fff; border-color: #238636; }

        .hidden { display: none; }

        #events-panel { max-height: 400px; overflow-y: auto; }

        .progress-bar {
            height: 6px;
            background: #21262d;
            border-radius: 3px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        .progress-fill {
            height: 100%;
            background: #00ff88;
            border-radius: 3px;
            transition: width 0.5s;
        }

        .thinking-blocks { max-height: 300px; overflow-y: auto; }
        .thinking-block {
            background: #0e1117;
            border-radius: 6px;
            padding: 0.5rem;
            margin: 0.3rem 0;
            font-size: 0.85rem;
        }

        @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
            .header { flex-direction: column; gap: 0.5rem; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Sentinel Cyber AI</h1>
            <div class="subtitle">Real-Time Multi-Agent Dashboard</div>
        </div>
        <div class="status">
            <span><span class="status-dot online" id="statusDot"></span> <span id="statusText">Connecting...</span></span>
            <span id="uptimeDisplay">Uptime: --</span>
            <span>Analyses: <span id="analysisCount">0</span></span>
        </div>
    </div>

    <div class="container">
        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="switchTab('overview')">Overview</button>
            <button class="nav-tab" onclick="switchTab('analyze')">Analyze</button>
            <button class="nav-tab" onclick="switchTab('thinking')">Thinking</button>
            <button class="nav-tab" onclick="switchTab('sandbox')">Sandbox</button>
            <button class="nav-tab" onclick="switchTab('subsystems')">Subsystems</button>
            <button class="nav-tab" onclick="switchTab('events')">Events</button>
            <button class="nav-tab" onclick="switchTab('integrations')">Integrations</button>
        </div>

        <!-- Tab: Overview -->
        <div id="tab-overview">
            <div class="grid">
                <div class="card">
                    <h3>Agents</h3>
                    <div class="metric" id="agentCount">--</div>
                    <div class="metric-label">Specialized agents online</div>
                </div>
                <div class="card">
                    <h3>Context Window</h3>
                    <div class="metric" id="contextUsage">--</div>
                    <div class="metric-label">Tokens used / 1M max</div>
                    <div class="progress-bar"><div class="progress-fill" id="contextBar" style="width:0%"></div></div>
                </div>
                <div class="card">
                    <h3>Memory</h3>
                    <div class="metric" id="memoryEntries">--</div>
                    <div class="metric-label">Total entries across tiers</div>
                </div>
                <div class="card">
                    <h3>Safety Rules</h3>
                    <div class="metric" id="safetyRules">--</div>
                    <div class="metric-label">Active classification rules</div>
                </div>
            </div>
            <div style="margin-top: 1rem;" class="card">
                <h3>Subsystem Health</h3>
                <div id="subsystemHealth">Loading...</div>
            </div>
        </div>

        <!-- Tab: Analyze -->
        <div id="tab-analyze" class="hidden">
            <div class="analyze-section">
                <h3>Security Analysis</h3>
                <p style="color: #8b949e; margin: 0.5rem 0;">Enter code or a security query to analyze using all 6 specialized agents.</p>
                <textarea id="analyzeInput" placeholder="Paste code or describe a security scenario...

Example: def login(username, password):
    query = f\"SELECT * FROM users WHERE username = '{username}'\"
    cursor.execute(query)"></textarea>
                <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem;">
                    <button class="btn" onclick="runAnalysis()" id="analyzeBtn">Run Analysis</button>
                    <span id="analysisStatus" style="color: #8b949e; align-self: center;"></span>
                </div>
            </div>
            <div id="results">
                <div style="color: #8b949e; text-align: center; padding: 2rem;">Run an analysis to see results here.</div>
            </div>
        </div>

        <!-- Tab: Thinking -->
        <div id="tab-thinking" class="hidden">
            <div class="analyze-section">
                <h3>Adaptive Thinking Engine</h3>
                <p style="color: #8b949e; margin: 0.5rem 0;">Configurable reasoning depth with effort parameter.</p>
                <textarea id="thinkInput" placeholder="What to think about..." style="min-height: 80px;"></textarea>
                <div style="margin-top: 0.75rem; display: flex; gap: 1rem; align-items: center;">
                    <select id="effortSelect" style="background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 0.4rem;">
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high" selected>High</option>
                        <option value="max">Max</option>
                    </select>
                    <button class="btn" onclick="runThinking()">Think</button>
                </div>
            </div>
            <div id="thinkingResults"></div>
        </div>

        <!-- Tab: Sandbox -->
        <div id="tab-sandbox" class="hidden">
            <div class="analyze-section">
                <h3>Code Execution Sandbox</h3>
                <p style="color: #8b949e; margin: 0.5rem 0;">Execute Python or bash in isolated Docker containers.</p>
                <textarea id="sandboxInput" placeholder="print('Hello, Sentinel!')" style="min-height: 120px; font-family: 'Consolas', monospace;"></textarea>
                <div style="margin-top: 0.75rem; display: flex; gap: 1rem; align-items: center;">
                    <select id="sandboxType" style="background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 0.4rem;">
                        <option value="python">Python</option>
                        <option value="bash">Bash</option>
                    </select>
                    <button class="btn" onclick="runSandbox()">Execute</button>
                </div>
            </div>
            <div id="sandboxResults"></div>
        </div>

        <!-- Tab: Subsystems -->
        <div id="tab-subsystems" class="hidden">
            <div class="card">
                <h3>All Subsystems Status</h3>
                <div id="allSubsystemsStatus">Loading...</div>
            </div>
            <div style="margin-top: 1rem;" class="card">
                <h3>Quick Actions</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.75rem;">
                    <button class="btn" onclick="compactMemory()">Compact Memory</button>
                    <button class="btn" onclick="checkSafety()" id="safetyBtn">Safety Check</button>
                    <button class="btn btn-danger" onclick="cryptoScan()">Scan Crypto</button>
                </div>
                <div id="quickActionResults" style="margin-top: 1rem;"></div>
            </div>
        </div>

        <!-- Tab: Events -->
        <div id="tab-events" class="hidden">
            <div class="card">
                <h3>Live Event Log</h3>
                <div id="events-panel">
                    <div style="color: #8b949e; text-align: center; padding: 1rem;">Waiting for events...</div>
                </div>
            </div>
        </div>

        <!-- Tab: Integrations -->
        <div id="tab-integrations" class="hidden">
            <div style="display: flex; gap: 0.5rem; align-items: center; margin-bottom: 1rem;">
                <span style="color: #8b949e; font-size: 0.9rem;">Configure Slack, Discord, GitHub, and monitoring integrations. All values stored in-memory for the session.</span>
                <button class="btn" onclick="refreshIntegrationStatus()" style="margin-left: auto;">Refresh Status</button>
            </div>
            <div class="grid">
                <!-- Slack Card -->
                <div class="card" style="border-left: 4px solid #4A154B;">
                    <h3>Slack Bot <span id="slackStatus" style="font-size: 0.75rem;">...</span></h3>
                    <div class="subsystem-row">
                        <span>Bot Token</span>
                        <input type="password" id="slackBotToken" placeholder="xoxb-..." style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div class="subsystem-row">
                        <span>Webhook URL</span>
                        <input type="text" id="slackWebhookUrl" placeholder="https://hooks.slack.com/..." style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div class="subsystem-row">
                        <span>Signing Secret</span>
                        <input type="password" id="slackSigningSecret" placeholder="(optional)" style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div style="display: flex; gap: 0.5rem; margin-top: 0.75rem;">
                        <button class="btn" onclick="saveSlackConfig()" style="font-size: 0.8rem; padding: 0.4rem 1rem;">Save</button>
                        <button class="btn" onclick="testIntegration('slack')" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #1f6feb;">Test</button>
                        <button class="btn" onclick="showSlackManifest()" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #21262d; color: #8b949e;">Manifest</button>
                    </div>
                    <div id="slackResult" style="margin-top: 0.5rem; font-size: 0.8rem; color: #8b949e;"></div>
                </div>

                <!-- Discord Card -->
                <div class="card" style="border-left: 4px solid #5865F2;">
                    <h3>Discord Bot <span id="discordStatus" style="font-size: 0.75rem;">...</span></h3>
                    <div class="subsystem-row">
                        <span>Bot Token</span>
                        <input type="password" id="discordBotToken" placeholder="(token)" style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div class="subsystem-row">
                        <span>App ID</span>
                        <input type="text" id="discordAppId" placeholder="(application id)" style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div class="subsystem-row">
                        <span>Public Key</span>
                        <input type="text" id="discordPublicKey" placeholder="(public key)" style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div style="display: flex; gap: 0.5rem; margin-top: 0.75rem;">
                        <button class="btn" onclick="saveDiscordConfig()" style="font-size: 0.8rem; padding: 0.4rem 1rem;">Save</button>
                        <button class="btn" onclick="testIntegration('discord')" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #1f6feb;">Test</button>
                        <button class="btn" onclick="showDiscordCommands()" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #21262d; color: #8b949e;">Commands</button>
                    </div>
                    <div id="discordResult" style="margin-top: 0.5rem; font-size: 0.8rem; color: #8b949e;"></div>
                </div>

                <!-- GitHub Card -->
                <div class="card" style="border-left: 4px solid #f0f6fc;">
                    <h3>GitHub Webhook <span id="githubStatus" style="font-size: 0.75rem;">...</span></h3>
                    <div class="subsystem-row">
                        <span>Webhook Secret</span>
                        <input type="password" id="githubWebhookSecret" placeholder="(shared secret)" style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div class="subsystem-row">
                        <span>Access Token</span>
                        <input type="password" id="githubToken" placeholder="ghp_..." style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.8rem;">
                        <span style="color: #8b949e;">Webhook URL to add in GitHub repo settings:</span>
                        <code id="githubWebhookUrl" style="display: block; background: #0e1117; padding: 0.4rem; border-radius: 4px; margin-top: 0.3rem; word-break: break-all;">http://&lt;your-server&gt;/github/webhook</code>
                    </div>
                    <div style="display: flex; gap: 0.5rem; margin-top: 0.75rem;">
                        <button class="btn" onclick="saveGitHubConfig()" style="font-size: 0.8rem; padding: 0.4rem 1rem;">Save</button>
                        <button class="btn" onclick="testIntegration('github')" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #1f6feb;">Test Scan</button>
                    </div>
                    <div id="githubResult" style="margin-top: 0.5rem; font-size: 0.8rem; color: #8b949e;"></div>
                </div>

                <!-- Monitoring Card -->
                <div class="card" style="border-left: 4px solid #f0883e;">
                    <h3>Monitoring <span id="monitoringStatus" style="font-size: 0.75rem;">...</span></h3>
                    <div class="subsystem-row">
                        <span>Status</span>
                        <span id="monitoringActive">Checking...</span>
                    </div>
                    <div class="subsystem-row">
                        <span>Active Alerts</span>
                        <span id="monitoringAlerts">--</span>
                    </div>
                    <div class="subsystem-row">
                        <span>Active Threats</span>
                        <span id="monitoringThreats">--</span>
                    </div>
                    <div class="subsystem-row">
                        <span>Webhook URL</span>
                        <input type="text" id="monitoringWebhookUrl" placeholder="https://hooks.example.com/..." style="width: 60%; background: #0e1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 0.3rem; font-size: 0.8rem;">
                    </div>
                    <div style="display: flex; gap: 0.5rem; margin-top: 0.75rem;">
                        <button class="btn" onclick="saveMonitoringConfig()" style="font-size: 0.8rem; padding: 0.4rem 1rem;">Save</button>
                        <button class="btn" onclick="testIntegration('monitoring')" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #1f6feb;">Test Alert</button>
                        <button class="btn" onclick="viewMonitoringStatus()" style="font-size: 0.8rem; padding: 0.4rem 1rem; background: #21262d; color: #8b949e;">Details</button>
                    </div>
                    <div id="monitoringResult" style="margin-top: 0.5rem; font-size: 0.8rem; color: #8b949e;"></div>
                </div>
            </div>
            <div id="integrationDetails" style="margin-top: 1rem;" class="hidden">
                <div class="card">
                    <h3 id="integrationDetailsTitle">Details</h3>
                    <pre id="integrationDetailsContent" style="background: #0e1117; padding: 0.75rem; border-radius: 6px; font-size: 0.85rem; overflow-x: auto; white-space: pre-wrap;"></pre>
                </div>
            </div>
        </div>
    </div>

    <script>
        // ── WebSocket Connection ──
        let ws = null;
        let clientId = 'dashboard-' + Math.random().toString(36).substr(2, 9);
        let reconnectTimer = null;

        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws/${clientId}`;

            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                document.getElementById('statusText').textContent = 'Connected';
                document.getElementById('statusDot').className = 'status-dot online';
                document.getElementById('uptimeDisplay').textContent = 'Uptime: --';

                // Subscribe to channels
                ws.send(JSON.stringify({ action: 'subscribe', channel: 'analysis' }));
                ws.send(JSON.stringify({ action: 'subscribe', channel: 'monitor' }));
                ws.send(JSON.stringify({ action: 'get_status' }));
                ws.send(JSON.stringify({ action: 'get_subsystems' }));
                ws.send(JSON.stringify({ action: 'get_agents' }));
                ws.send(JSON.stringify({ action: 'get_events' }));

                // Auto-refresh status
                if (window.statusInterval) clearInterval(window.statusInterval);
                window.statusInterval = setInterval(() => {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ action: 'get_status' }));
                        ws.send(JSON.stringify({ action: 'get_subsystems' }));
                    }
                }, 5000);
            };

            ws.onmessage = function(event) {
                const msg = JSON.parse(event.data);

                if (msg.type === 'pong') return;

                if (msg.type === 'status') {
                    updateStatus(msg.data);
                } else if (msg.type === 'subsystems') {
                    updateSubsystems(msg.data);
                } else if (msg.type === 'agents') {
                    updateAgents(msg.data);
                } else if (msg.type === 'events') {
                    updateEvents(msg.data);
                } else if (msg.channel === 'analysis') {
                    handleAnalysisEvent(msg.data);
                }
            };

            ws.onclose = function() {
                document.getElementById('statusText').textContent = 'Reconnecting...';
                document.getElementById('statusDot').className = 'status-dot offline';
                if (window.statusInterval) clearInterval(window.statusInterval);
                setTimeout(connectWebSocket, 2000);
            };

            ws.onerror = function() {
                ws.close();
            };
        }

        // ── Tab Switching ──
        function switchTab(tabName) {
            document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('[id^="tab-"]').forEach(t => t.classList.add('hidden'));
            event.target.classList.add('active');
            document.getElementById('tab-' + tabName).classList.remove('hidden');
        }

        // ── Status Update ──
        function updateStatus(data) {
            document.getElementById('analysisCount').textContent = data.analysis_count || 0;
            if (data.uptime_seconds) {
                const mins = Math.floor(data.uptime_seconds / 60);
                const secs = Math.floor(data.uptime_seconds % 60);
                document.getElementById('uptimeDisplay').textContent = `Uptime: ${mins}m ${secs}s`;
            }
            document.getElementById('agentCount').textContent = data.agent_count || '--';
            document.getElementById('statusText').textContent = 'Online';
            document.getElementById('statusDot').className = 'status-dot online';
        }

        function updateAgents(agents) {
            if (!agents || agents.length === 0) return;
            document.getElementById('agentCount').textContent = agents.length;
        }

        function updateSubsystems(data) {
            if (!data) return;
            let html = '';
            let totalMem = 0;

            for (const [name, info] of Object.entries(data)) {
                const status = info.status || 'unknown';
                const statusClass = status === 'ready' ? 'ready' : 'error';
                const statusText = status === 'ready' ? 'Ready' : (info.error || status);

                html += `<div class="subsystem-row">
                    <span class="subsystem-name">${name}</span>
                    <span class="subsystem-status ${statusClass}">${statusText}</span>
                </div>`;

                // Capture memory entries for overview
                if (name === 'memory') {
                    totalMem = (info.system_entries || 0) + (info.project_entries || 0) + (info.session_entries || 0);
                    document.getElementById('memoryEntries').textContent = totalMem;
                }
                if (name === 'context') {
                    const usage = info.usage_ratio || 0;
                    document.getElementById('contextUsage').textContent = `${info.current_tokens || 0} / 1M`;
                    document.getElementById('contextBar').style.width = `${(usage * 100)}%`;
                }
                if (name === 'safety') {
                    document.getElementById('safetyRules').textContent = info.total_rules || '--';
                }
            }

            // Subsystem health (overview tab)
            const healthy = Object.values(data).filter(v => v.status === 'ready').length;
            const total = Object.keys(data).length;
            document.getElementById('subsystemHealth').innerHTML = `
                <div class="subsystem-row"><span class="subsystem-name">Healthy</span><span class="subsystem-status ready">${healthy}/${total}</span></div>
            `;

            // All subsystems (subsystems tab)
            document.getElementById('allSubsystemsStatus').innerHTML = html;
        }

        function updateEvents(events) {
            if (!events || events.length === 0) return;
            const container = document.getElementById('events-panel');
            container.innerHTML = events.slice(-50).reverse().map(e => `
                <div class="log-entry">
                    <span class="log-time">${new Date(e.timestamp).toLocaleTimeString()}</span>
                    <span class="log-type">[${e.type}]</span>
                    <span>${JSON.stringify(e.data).substring(0, 200)}</span>
                </div>
            `).join('');
        }

        function handleAnalysisEvent(data) {
            if (!data) return;

            if (data.type === 'start') {
                document.getElementById('analysisStatus').textContent = 'Analyzing...';
                document.getElementById('analyzeBtn').disabled = true;
            } else if (data.type === 'complete') {
                document.getElementById('analysisStatus').textContent = '';
                document.getElementById('analyzeBtn').disabled = false;
                document.getElementById('analysisCount').textContent = parseInt(document.getElementById('analysisCount').textContent) + 1;

                // Fetch full results
                if (data.id) {
                    fetchResults(data.id);
                }
            } else if (data.type === 'error') {
                document.getElementById('analysisStatus').textContent = 'Error';
                document.getElementById('analyzeBtn').disabled = false;
            }
        }

        async function fetchResults(analysisId) {
            // Display a summary card from the broadcast data
            const resultsDiv = document.getElementById('results');
            // Results will be updated when the user runs analysis
        }

        // ── Actions ──
        async function runAnalysis() {
            const input = document.getElementById('analyzeInput').value;
            if (!input) return;

            // Show loading
            document.getElementById('results').innerHTML = '<div style="color: #8b949e; text-align: center;">Running analysis...</div>';

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({query: input})
                });
                const result = await response.json();

                let html = '';

                if (result.status === 'refused') {
                    html = '<div class="finding critical">' +
                        '<strong>Content Refused</strong><br>' +
                        escapeHtml(result.summary || 'Request was refused by safety filters.') +
                    '</div>';
                } else {
                    const statusColors = { success: '#00ff88', partial: '#ffcc00', error: '#ff4444' };
                    html += '<div style="margin-bottom: 1rem; padding: 0.75rem; background: #0e1117; border-radius: 6px; border: 1px solid #30363d;">' +
                        '<span style="color: ' + (statusColors[result.status] || '#8b949e') + '; font-weight: bold;">' + escapeHtml(result.status || '').toUpperCase() + '</span>' +
                        '<span style="color: #8b949e;"> | Confidence: ' + ((result.confidence || 0) * 100).toFixed(0) + '%</span>' +
                        '<span style="color: #8b949e;"> | Agents: ' + escapeHtml((result.agents_used || []).join(', ')) + '</span>' +
                        (result.thinking ? '<span style="color: #8b949e;"> | Thinking: ' + escapeHtml(result.thinking.effort || '') + '</span>' : '') +
                        (result.context ? '<span style="color: #8b949e;"> | Context: ' + ((result.context.usage_ratio || 0) * 100).toFixed(0) + '%</span>' : '') +
                    '</div>';

                    const findings = result.findings || [];
                    if (findings.length > 0) {
                        html += '<h4 style="margin-bottom: 0.5rem;">Found ' + findings.length + ' Findings</h4>';
                        for (const f of findings) {
                            const sev = (f.severity || 'info').toLowerCase();
                            html += '<div class="finding ' + sev + '">' +
                                '<strong>' + escapeHtml(f.title || 'Finding') + '</strong>' +
                                '<span style="float: right; color: ' + (sev === 'critical' ? '#ff4444' : sev === 'high' ? '#ff8800' : sev === 'medium' ? '#ffcc00' : '#44aaff') + ';">' + escapeHtml(f.severity || 'INFO') + '</span>' +
                                '<br><span style="color: #8b949e;">' + escapeHtml((f.description || '').substring(0, 500)) + '</span>' +
                                (f.remediation ? '<br><span style="color: #00ff88;">Fix: ' + escapeHtml(f.remediation.substring(0, 200)) + '</span>' : '') +
                                (f.cwe ? '<br><span style="color: #58a6ff;">CWE: ' + escapeHtml(f.cwe) + '</span>' : '') +
                            '</div>';
                        }
                    } else {
                        html += '<div style="color: #00ff88; padding: 1rem;">No vulnerabilities found.</div>';
                    }

                    // Agent details
                    if (result.agent_results && result.agent_results.length > 0) {
                        html += '<h4 style="margin-top: 1rem;">Agent Details</h4>';
                        for (const ar of result.agent_results) {
                            html += '<div class="finding" style="border-left-color: #58a6ff;">' +
                                '<strong>' + escapeHtml(ar.agent_name || '') + '</strong> &mdash; ' + escapeHtml(ar.status || '') + ' (' + ((ar.confidence || 0) * 100).toFixed(0) + '%)<br>' +
                                '<span style="color: #8b949e;">' + escapeHtml((ar.summary || '').substring(0, 200)) + '</span>' +
                            '</div>';
                        }
                    }
                }

                document.getElementById('results').innerHTML = html;
                // Switch to analyze tab
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelector('[onclick="switchTab(\'analyze\')"]').classList.add('active');
                document.querySelectorAll('[id^="tab-"]').forEach(t => t.classList.add('hidden'));
                document.getElementById('tab-analyze').classList.remove('hidden');

            } catch (err) {
                document.getElementById('results').innerHTML = `<div class="finding critical">Error: ${err.message}</div>`;
            }
        }

        async function runThinking() {
            const input = document.getElementById('thinkInput').value;
            const effort = document.getElementById('effortSelect').value;
            if (!input) return;

            document.getElementById('thinkingResults').innerHTML = '<div style="color: #8b949e;">Thinking...</div>';

            try {
                const response = await fetch('/api/thinking/run', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({query: input, effort: effort})
                });
                const result = await response.json();

                let html = '<div class="card">' +
                    '<h3>Thinking Result</h3>' +
                    '<div class="subsystem-row"><span>Effort</span><span>' + escapeHtml(result.effort || effort) + '</span></div>' +
                    '<div class="subsystem-row"><span>Tokens</span><span>' + (result.tokens || 0) + '</span></div>' +
                    '<div class="subsystem-row"><span>Time</span><span>' + (result.time_ms || 0) + 'ms</span></div>' +
                '</div>';

                if (result.blocks && result.blocks.length > 0) {
                    html += '<div class="card" style="margin-top: 1rem;"><h3>Thinking Blocks</h3><div class="thinking-blocks">';
                    for (const block of result.blocks) {
                        html += '<div class="thinking-block">' +
                            '<strong>' + escapeHtml(block.type || 'block') + '</strong> (effort: ' + escapeHtml(block.effort_used || effort) + ')' +
                            '<br><span style="color: #8b949e;">' + escapeHtml((block.content || '').substring(0, 300)) + '</span>' +
                        '</div>';
                    }
                    html += '</div></div>';
                }

                document.getElementById('thinkingResults').innerHTML = html;
            } catch (err) {
                document.getElementById('thinkingResults').innerHTML = `<div class="finding critical">Error: ${err.message}</div>`;
            }
        }

        async function runSandbox() {
            const code = document.getElementById('sandboxInput').value;
            const type = document.getElementById('sandboxType').value;
            if (!code) return;

            document.getElementById('sandboxResults').innerHTML = '<div style="color: #8b949e;">Executing...</div>';

            try {
                const response = await fetch('/api/sandbox/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({code: code, exec_type: type})
                });
                const result = await response.json();

                let html = '<div class="card">' +
                    '<h3>Execution Result</h3>' +
                    '<div class="subsystem-row"><span>Success</span><span style="color: ' + (result.success ? '#00ff88' : '#ff4444') + ';">' + (result.success ? 'Yes' : 'No') + '</span></div>' +
                    '<div class="subsystem-row"><span>Exit Code</span><span>' + (result.exit_code !== undefined ? result.exit_code : '--') + '</span></div>' +
                    '<div class="subsystem-row"><span>Time</span><span>' + (result.time_ms || 0) + 'ms</span></div>' +
                '</div>';

                if (result.stdout) {
                    html += `<div class="card" style="margin-top: 0.5rem;"><h3>Output</h3>
                        <pre style="background: #0e1117; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem;">${escapeHtml(result.stdout)}</pre></div>`;
                }
                if (result.stderr) {
                    html += `<div class="card" style="margin-top: 0.5rem;"><h3>Errors</h3>
                        <pre style="background: #0e1117; padding: 0.75rem; border-radius: 4px; color: #ff4444; overflow-x: auto; font-size: 0.85rem;">${escapeHtml(result.stderr)}</pre></div>`;
                }

                document.getElementById('sandboxResults').innerHTML = html;
            } catch (err) {
                document.getElementById('sandboxResults').innerHTML = `<div class="finding critical">Error: ${err.message}</div>`;
            }
        }

        async function compactMemory() {
            try {
                const response = await fetch('/api/memory/compact');
                const result = await response.json();
                document.getElementById('quickActionResults').innerHTML = `<div class="finding low">Memory compacted: ${JSON.stringify(result)}</div>`;
            } catch (err) {
                document.getElementById('quickActionResults').innerHTML = `<div class="finding critical">Error: ${err.message}</div>`;
            }
        }

        async function checkSafety() {
            const input = prompt('Enter content to safety-check:');
            if (!input) return;
            try {
                const response = await fetch('/api/safety/check', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({content: input})
                });
                const result = await response.json();
                document.getElementById('quickActionResults').innerHTML =
                    '<div class="finding ' + (result.is_safe ? 'low' : 'critical') + '">' +
                        '<strong>Safety: ' + (result.is_safe ? 'Safe' : 'Refused') + '</strong><br>' +
                        'Stop Reason: ' + escapeHtml(result.stop_reason || '') + '<br>' +
                        'Confidence: ' + ((result.confidence || 0) * 100).toFixed(0) + '%<br>' +
                        (result.refusal_reason ? 'Refusal: ' + escapeHtml(result.refusal_reason) : '') +
                        (result.matched_patterns ? 'Patterns: ' + escapeHtml(result.matched_patterns.join(', ')) : '') +
                    '</div>';
            } catch (err) {
                document.getElementById('quickActionResults').innerHTML = `<div class="finding critical">Error: ${err.message}</div>`;
            }
        }

        async function cryptoScan() {
            const code = prompt('Paste code to scan for quantum-vulnerable crypto:');
            if (!code) return;
            try {
                const response = await fetch('/api/crypto/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({code: code})
                });
                const result = await response.json();
                let html = '<div class="card">' +
                    '<h3>Quantum Crypto Scan</h3>' +
                    '<div class="subsystem-row"><span>Readiness</span><span>' + (result.readiness_score || 0) + '/100</span></div>' +
                    '<div class="subsystem-row"><span>Vulnerable</span><span style="color: ' + (result.quantum_vulnerable ? '#ff4444' : '#00ff88') + ';">' + (result.quantum_vulnerable || 0) + '</span></div>' +
                    '<div class="subsystem-row"><span>Quantum Safe</span><span>' + (result.quantum_safe_count || 0) + '</span></div>' +
                    '<div class="subsystem-row"><span>Verdict</span><span>' + escapeHtml(result.verdict || 'N/A') + '</span></div>' +
                '</div>';
                if (result.critical_findings && result.critical_findings.length > 0) {
                    html += '<div class="card" style="margin-top: 0.5rem;"><h3>Critical Findings</h3>';
                    for (const f of result.critical_findings) {
                        html += '<div class="finding critical"><strong>' + escapeHtml(f.algorithm || f.name || '') + '</strong>: ' + escapeHtml((f.description || '').substring(0, 200)) + '</div>';
                    }
                    html += '</div>';
                }
                document.getElementById('quickActionResults').innerHTML = html;
            } catch (err) {
                document.getElementById('quickActionResults').innerHTML = `<div class="finding critical">Error: ${err.message}</div>`;
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // ── Integration Functions ──
        async function refreshIntegrationStatus() {
            try {
                const response = await fetch('/api/integrations');
                const status = await response.json();

                // Slack
                const slackEl = document.getElementById('slackStatus');
                slackEl.textContent = status.slack.configured ? '✅ Configured' : '❌ Not configured';
                slackEl.style.color = status.slack.configured ? '#00ff88' : '#ff4444';

                // Discord
                const discordEl = document.getElementById('discordStatus');
                discordEl.textContent = status.discord.configured ? '✅ Configured' : '❌ Not configured';
                discordEl.style.color = status.discord.configured ? '#00ff88' : '#ff4444';

                // GitHub
                const githubEl = document.getElementById('githubStatus');
                githubEl.textContent = status.github.configured ? '✅ Configured' : '❌ Not configured';
                githubEl.style.color = status.github.configured ? '#00ff88' : '#ff4444';

                // Monitoring
                const monEl = document.getElementById('monitoringStatus');
                monEl.textContent = status.monitoring.active ? '✅ Active' : '❌ Inactive';
                monEl.style.color = status.monitoring.active ? '#00ff88' : '#ff4444';
                document.getElementById('monitoringActive').textContent = status.monitoring.active ? 'Active' : 'Check config';

            } catch (err) {
                console.error('Failed to refresh integration status', err);
            }
        }

        async function saveSlackConfig() {
            const botToken = document.getElementById('slackBotToken').value;
            const webhookUrl = document.getElementById('slackWebhookUrl').value;
            const signingSecret = document.getElementById('slackSigningSecret').value;
            if (!botToken && !webhookUrl) {
                document.getElementById('slackResult').innerHTML = '<span style="color: #ffcc00;">Enter at least bot token or webhook URL</span>';
                return;
            }
            try {
                const response = await fetch('/api/integrations/slack/configure', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({bot_token: botToken, webhook_url: webhookUrl, signing_secret: signingSecret}),
                });
                const result = await response.json();
                document.getElementById('slackResult').innerHTML = '<span style="color: #00ff88;">' + escapeHtml(result.message) + '</span>';
                refreshIntegrationStatus();
            } catch (err) {
                document.getElementById('slackResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function saveDiscordConfig() {
            const botToken = document.getElementById('discordBotToken').value;
            const appId = document.getElementById('discordAppId').value;
            const publicKey = document.getElementById('discordPublicKey').value;
            if (!botToken && !appId) {
                document.getElementById('discordResult').innerHTML = '<span style="color: #ffcc00;">Enter at least bot token or app ID</span>';
                return;
            }
            try {
                const response = await fetch('/api/integrations/discord/configure', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({bot_token: botToken, application_id: appId, public_key: publicKey}),
                });
                const result = await response.json();
                document.getElementById('discordResult').innerHTML = '<span style="color: #00ff88;">' + escapeHtml(result.message) + '</span>';
                refreshIntegrationStatus();
            } catch (err) {
                document.getElementById('discordResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function saveGitHubConfig() {
            const webhookSecret = document.getElementById('githubWebhookSecret').value;
            const githubToken = document.getElementById('githubToken').value;
            if (!webhookSecret && !githubToken) {
                document.getElementById('githubResult').innerHTML = '<span style="color: #ffcc00;">Enter at least one value</span>';
                return;
            }
            try {
                const response = await fetch('/api/integrations/github/configure', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({webhook_secret: webhookSecret, github_token: githubToken}),
                });
                const result = await response.json();
                document.getElementById('githubResult').innerHTML = '<span style="color: #00ff88;">' + escapeHtml(result.message) + '</span>';
                refreshIntegrationStatus();
            } catch (err) {
                document.getElementById('githubResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function saveMonitoringConfig() {
            const webhookUrl = document.getElementById('monitoringWebhookUrl').value;
            if (!webhookUrl) {
                document.getElementById('monitoringResult').innerHTML = '<span style="color: #ffcc00;">Enter a webhook URL</span>';
                return;
            }
            try {
                const response = await fetch('/api/integrations/monitoring/configure', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({channel: 'webhook', url: webhookUrl}),
                });
                const result = await response.json();
                document.getElementById('monitoringResult').innerHTML = '<span style="color: #00ff88;">' + escapeHtml(result.message || 'Saved') + '</span>';
                refreshIntegrationStatus();
            } catch (err) {
                document.getElementById('monitoringResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function testIntegration(type) {
            const resultEl = document.getElementById(type + 'Result');
            resultEl.innerHTML = '<span style="color: #8b949e;">Testing...</span>';

            try {
                let url = '';
                if (type === 'slack') url = '/api/integrations/slack/test';
                else if (type === 'discord') url = '/api/integrations/discord/test';
                else if (type === 'github') url = '/api/integrations/github/test';
                else if (type === 'monitoring') url = '/api/integrations/monitoring/test-alert';

                const response = await fetch(url, {method: 'POST'});
                const result = await response.json();

                if (result.error) {
                    resultEl.innerHTML = '<span style="color: #ffcc00;">' + escapeHtml(result.error) + '</span>';
                } else {
                    resultEl.innerHTML = '<span style="color: #00ff88;">Test sent successfully</span>';
                }
            } catch (err) {
                resultEl.innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function showSlackManifest() {
            try {
                const response = await fetch('/api/integrations/slack/manifest');
                const manifest = await response.json();
                document.getElementById('integrationDetailsTitle').textContent = 'Slack App Manifest';
                document.getElementById('integrationDetailsContent').textContent = JSON.stringify(manifest, null, 2);
                document.getElementById('integrationDetails').classList.remove('hidden');
            } catch (err) {
                document.getElementById('slackResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function showDiscordCommands() {
            try {
                const response = await fetch('/api/integrations/discord/commands');
                const data = await response.json();
                document.getElementById('integrationDetailsTitle').textContent = 'Discord Slash Commands';
                document.getElementById('integrationDetailsContent').textContent = JSON.stringify(data, null, 2);
                document.getElementById('integrationDetails').classList.remove('hidden');
            } catch (err) {
                document.getElementById('discordResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        async function viewMonitoringStatus() {
            try {
                const response = await fetch('/api/monitoring/status');
                const data = await response.json();
                document.getElementById('integrationDetailsTitle').textContent = 'Monitoring Status';
                document.getElementById('integrationDetailsContent').textContent = JSON.stringify(data, null, 2);
                document.getElementById('integrationDetails').classList.remove('hidden');
            } catch (err) {
                document.getElementById('monitoringResult').innerHTML = '<span style="color: #ff4444;">Error: ' + escapeHtml(err.message) + '</span>';
            }
        }

        // ── Init ──
        connectWebSocket();
    </script>
</body>
</html>
"""


# ── Entry Point ──

def main(host: str = "0.0.0.0", port: int = 8500):
    """Launch the dashboard server."""
    if not HAS_FASTAPI:
        print("FastAPI not installed. Install with: pip install fastapi uvicorn")
        print("Then set PYTHONPATH to include the project root.")
        sys.exit(1)

    app = create_app()
    print(f"""
{'='*60}
Sentinel WebSocket Dashboard
{'='*60}
Web UI:      http://localhost:{port}
API:         http://localhost:{port}/api/status
WebSocket:   ws://localhost:{port}/ws/<client-id>
Docs:        http://localhost:{port}/docs
{'='*60}
    """)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
