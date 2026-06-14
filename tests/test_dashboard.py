"""
Tests for the Sentinel WebSocket Dashboard Server.

Covers:
- ConnectionManager (WebSocket connection tracking, subscriptions, broadcasting)
- DashboardApp system status and event logging
- API endpoint data integrity
- HTML dashboard content
"""

import os
import sys
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── ConnectionManager Tests ──

class TestConnectionManager:
    """Test WebSocket connection manager."""

    @pytest.mark.asyncio
    async def test_connect_disconnect(self):
        """Test connection tracking and cleanup."""
        from src.dashboard.dashboard_server import ConnectionManager

        cm = ConnectionManager()
        ws_mock = AsyncMock()

        # Connect
        await cm.connect(ws_mock, "client-1")
        assert "client-1" in cm.active_connections
        assert cm.active_connections["client-1"] == ws_mock
        ws_mock.accept.assert_awaited_once()

        # Disconnect
        cm.disconnect("client-1")
        assert "client-1" not in cm.active_connections

    def test_subscribe_channels(self):
        """Test subscribing to channels."""
        from src.dashboard.dashboard_server import ConnectionManager

        cm = ConnectionManager()

        # Valid channel
        assert cm.subscribe("client-1", "analysis") is True
        assert "client-1" in cm.subscriptions["analysis"]

        # Invalid channel
        assert cm.subscribe("client-1", "nonexistent") is False
        assert "client-1" not in cm.subscriptions.get("nonexistent", set())

    def test_unsubscribe(self):
        """Test unsubscribing from channels."""
        from src.dashboard.dashboard_server import ConnectionManager

        cm = ConnectionManager()
        cm.subscribe("client-1", "monitor")
        assert "client-1" in cm.subscriptions["monitor"]

        cm.unsubscribe("client-1", "monitor")
        assert "client-1" not in cm.subscriptions["monitor"]

    @pytest.mark.asyncio
    async def test_broadcast_to_subscribers(self):
        """Test broadcasting only reaches subscribers."""
        from src.dashboard.dashboard_server import ConnectionManager

        cm = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()

        await cm.connect(ws1, "client-1")
        await cm.connect(ws2, "client-2")

        cm.subscribe("client-1", "analysis")
        # client-2 NOT subscribed to analysis

        await cm.broadcast("analysis", {"test": "data"})

        # Only client-1 should receive
        ws1.send_json.assert_awaited_once()
        ws2.send_json.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_broadcast_disconnected_client(self):
        """Test broadcast handles disconnected clients gracefully."""
        from src.dashboard.dashboard_server import ConnectionManager

        cm = ConnectionManager()
        ws = AsyncMock()
        await cm.connect(ws, "client-1")
        cm.subscribe("client-1", "analysis")

        # Simulate disconnection by removing from active
        cm.active_connections.pop("client-1")

        # Should not raise
        await cm.broadcast("analysis", {"test": "data"})
        assert "client-1" not in cm.subscriptions["analysis"]

    def test_default_channels_exist(self):
        """Test all expected default channels are present."""
        from src.dashboard.dashboard_server import ConnectionManager

        cm = ConnectionManager()
        expected = {"analysis", "monitor", "thinking", "sandbox", "safety", "memory", "neural", "agents"}
        assert set(cm.subscriptions.keys()) == expected


# ── DashboardApp Tests ──

class TestDashboardApp:
    """Test DashboardApp system status and event logging."""

    def test_init(self):
        """Test DashboardApp initialization."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        assert app._analysis_count == 0
        assert app._event_log == []
        assert app._max_log_entries == 500
        assert app.orchestrator is None
        assert app._start_time > 0

    def test_get_system_status_no_orchestrator(self):
        """Test system status returns defaults when orchestrator not initialized."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        status = app.get_system_status()

        assert "uptime_seconds" in status
        assert status["analysis_count"] == 0
        assert status["active_websockets"] == 0
        assert status["agent_count"] == 0
        assert "memory_usage_mb" in status
        assert "timestamp" in status

    def test_get_agent_status_no_orchestrator(self):
        """Test agent status returns empty list when no orchestrator."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        assert app.get_agent_status() == []

    def test_get_subsystem_status_no_orchestrator(self):
        """Test subsystem status returns empty dict when no orchestrator."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        assert app.get_subsystem_status() == {}

    def test_log_event(self):
        """Test event logging."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        event = app.log_event("test_event", {"key": "value"})

        assert event["type"] == "test_event"
        assert event["data"] == {"key": "value"}
        assert len(event["id"]) == 8
        assert "timestamp" in event
        assert len(app._event_log) == 1

    def test_log_event_max_entries(self):
        """Test event log respects max entries limit."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        app._max_log_entries = 10

        for i in range(15):
            app.log_event("test", {"i": i})

        assert len(app._event_log) == 10
        assert app._event_log[0]["data"]["i"] == 5  # First remaining

    @pytest.mark.asyncio
    @patch("src.dashboard.dashboard_server.DashboardApp.init_orchestrator")
    async def test_run_analysis_fails_gracefully(self, mock_init):
        """Test analysis failure returns error dict."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        mock_init.return_value = True
        app.orchestrator = MagicMock()
        app.orchestrator.process = AsyncMock(side_effect=Exception("Analysis crashed"))

        result = await app.run_analysis("test")
        assert result["status"] == "error"
        assert "Analysis crashed" in result.get("error", "")

    @pytest.mark.asyncio
    @patch("src.dashboard.dashboard_server.DashboardApp.init_orchestrator")
    async def test_run_analysis_success(self, mock_init):
        """Test successful analysis returns result."""
        from src.dashboard.dashboard_server import DashboardApp

        app = DashboardApp()
        mock_init.return_value = True
        app.orchestrator = MagicMock()
        app.orchestrator.process = AsyncMock(return_value={
            "status": "success",
            "findings": [{"title": "SQL Injection", "severity": "CRITICAL"}],
            "summary": "Found 1 issue",
            "confidence": 0.95,
            "agents_used": ["Code-Scanner"],
            "thinking": {"effort": "high"},
            "context": {"usage_ratio": 0.3},
        })

        result = await app.run_analysis("test query")
        assert result["status"] == "success"
        assert len(result["findings"]) == 1


# ── API Endpoint Data Integrity Tests ──

class TestAPIEndpoints:
    """Test API endpoint data structures."""

    def test_routes_exist(self):
        """Test all critical API routes are registered."""
        from src.dashboard.dashboard_server import create_app

        app = create_app()
        routes = [r.path for r in app.routes if hasattr(r, "path")]

        critical_endpoints = [
            "/api/status", "/api/agents", "/api/subsystems", "/api/events",
            "/api/analyze", "/api/thinking/status", "/api/thinking/run",
            "/api/memory/status", "/api/memory/add", "/api/memory/compact",
            "/api/context/status", "/api/safety/check", "/api/sandbox/execute",
            "/api/vision/analyze", "/api/learning/status", "/api/neural/status",
            "/api/monitoring/status", "/api/crypto/scan", "/api/supplychain/analyze",
            "/api/pentest/status", "/api/adversarial/stats", "/api/cluster/status",
        ]

        for endpoint in critical_endpoints:
            matching = [r for r in routes if endpoint in r]
            assert len(matching) > 0, f"Missing endpoint: {endpoint}"

    def test_sensitive_endpoints_use_post(self):
        """Test sensitive endpoints use POST method."""
        from src.dashboard.dashboard_server import create_app

        app = create_app()

        post_endpoints = ["/api/analyze", "/api/thinking/run", "/api/memory/add",
                          "/api/memory/compact", "/api/safety/check",
                          "/api/sandbox/execute", "/api/vision/analyze",
                          "/api/crypto/scan", "/api/supplychain/analyze"]

        for path in post_endpoints:
            route = next((r for r in app.routes if hasattr(r, "path") and r.path == path), None)
            if route and hasattr(route, "methods"):
                assert "POST" in route.methods, f"{path} should use POST (got {route.methods})"

    def test_read_only_endpoints_use_get(self):
        """Test read-only endpoints use GET method."""
        from src.dashboard.dashboard_server import create_app

        app = create_app()

        get_endpoints = ["/api/status", "/api/agents", "/api/subsystems", "/api/events",
                         "/api/thinking/status", "/api/memory/status", "/api/context/status",
                         "/api/learning/status", "/api/neural/status", "/api/monitoring/status"]

        for path in get_endpoints:
            route = next((r for r in app.routes if hasattr(r, "path") and r.path == path), None)
            if route and hasattr(route, "methods"):
                assert "GET" in route.methods, f"{path} should use GET (got {route.methods})"

    def test_websocket_endpoint_exists(self):
        """Test WebSocket endpoint is registered."""
        from src.dashboard.dashboard_server import create_app

        app = create_app()
        ws_routes = [r for r in app.routes if hasattr(r, "path") and "/ws/" in r.path]
        assert len(ws_routes) > 0

    def test_dashboard_html_has_escape_html(self):
        """Test the HTML dashboard uses escapeHtml for XSS protection."""
        from src.dashboard.dashboard_server import HTML_DASHBOARD

        assert "function escapeHtml" in HTML_DASHBOARD
        assert "escapeHtml(" in HTML_DASHBOARD


# ── HTML Dashboard Content Tests ──

class TestHTMLDashboard:
    """Test the inline HTML dashboard content."""

    def test_html_structure(self):
        """Test HTML dashboard has required structure."""
        from src.dashboard.dashboard_server import HTML_DASHBOARD

        assert "<!DOCTYPE html>" in HTML_DASHBOARD
        assert "<body>" in HTML_DASHBOARD
        assert "</html>" in HTML_DASHBOARD
        assert "Sentinel Cyber AI" in HTML_DASHBOARD
        assert "WebSocket" in HTML_DASHBOARD

    def test_css_included(self):
        """Test CSS styling is included."""
        from src.dashboard.dashboard_server import HTML_DASHBOARD

        assert ".header" in HTML_DASHBOARD
        assert ".card" in HTML_DASHBOARD
        assert ".btn" in HTML_DASHBOARD
        assert "@media" in HTML_DASHBOARD  # Responsive design

    def test_tabs_exist(self):
        """Test all navigation tabs exist."""
        from src.dashboard.dashboard_server import HTML_DASHBOARD

        tabs = ["Overview", "Analyze", "Thinking", "Sandbox", "Subsystems", "Events"]
        for tab in tabs:
            assert tab in HTML_DASHBOARD

    def test_js_functions_exist(self):
        """Test all required JavaScript functions exist."""
        from src.dashboard.dashboard_server import HTML_DASHBOARD

        functions = [
            "connectWebSocket", "switchTab", "runAnalysis", "runThinking",
            "runSandbox", "compactMemory", "checkSafety", "cryptoScan",
            "escapeHtml", "updateStatus", "updateSubsystems",
            "handleAnalysisEvent",
        ]
        for func in functions:
            assert f"function {func}" in HTML_DASHBOARD, f"Missing JS function: {func}"

    def test_html_contains_connect_websocket(self):
        """Test the dashboard auto-connects via WebSocket."""
        from src.dashboard.dashboard_server import HTML_DASHBOARD

        assert "connectWebSocket()" in HTML_DASHBOARD


# ── Main Entry Point Tests ──

@patch("src.dashboard.dashboard_server.HAS_FASTAPI", False)
@patch("src.dashboard.dashboard_server.sys.exit", side_effect=SystemExit(1))
def test_main_no_fastapi_exits_gracefully(mock_exit):
    """Test main exits gracefully when FastAPI not installed."""
    from src.dashboard.dashboard_server import main
    try:
        main()
    except SystemExit:
        pass
    mock_exit.assert_called_once_with(1)


@patch("src.dashboard.dashboard_server.HAS_FASTAPI", True)
@patch("src.dashboard.dashboard_server.uvicorn.run")
def test_main_starts_server(mock_uvicorn):
    """Test main starts uvicorn when FastAPI is available."""
    from src.dashboard.dashboard_server import main
    main()
    mock_uvicorn.assert_called_once()
