"""
End-to-end tests for webhook integrations and bot interactions.

Covers:
- GitHub webhook: push events, file filtering, signature verification
- Slack bot: slash command parsing, response generation, manifest
- Discord bot: interaction handling, command routing, embeds
- Monitoring: alert delivery, threat tracking, metrics
"""

import os
import sys
import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── GitHub Webhook Tests ──

class TestGitHubWebhook:
    """Test GitHub webhook event handling."""

    def test_signature_verification_valid(self):
        """Test webhook signature verification with valid signature."""
        from src.integrations.github_webhook import GitHubWebhookHandler
        import hmac, hashlib

        handler = GitHubWebhookHandler(webhook_secret="test-secret")
        body = b'{"test": "payload"}'
        signature = "sha256=" + hmac.new(
            b"test-secret", body, hashlib.sha256
        ).hexdigest()

        assert handler.verify_signature(signature, body) is True

    def test_signature_verification_invalid(self):
        """Test webhook signature verification rejects invalid signature."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler(webhook_secret="test-secret")
        body = b'{"test": "payload"}'

        assert handler.verify_signature("sha256=invalid", body) is False

    def test_signature_verification_no_secret(self):
        """Test webhook skips verification when no secret configured."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler()
        assert handler.verify_signature("", b"test") is True

    @pytest.mark.asyncio
    async def test_push_event_no_commits(self):
        """Test push event with no commits returns None."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler()
        payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "test/repo"},
            "commits": [],
        }
        result = await handler.handle_webhook("push", payload, {})
        assert result["status"] == "ok"
        assert result["scan"] is None

    @pytest.mark.asyncio
    async def test_push_event_file_filtering(self):
        """Test push event filters to supported source files."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler()
        handler._orchestrator = AsyncMock()

        payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "test/repo"},
            "commits": [{
                "id": "abc123",
                "message": "test commit",
                "author": {"name": "Tester"},
                "added": ["src/app.py", "README.md", "image.png"],
                "modified": ["src/utils.js", "docs/index.html"],
                "removed": [],
            }],
        }
        result = await handler.handle_webhook("push", payload, {})
        assert result["status"] == "ok"
        # Only .py and .js files should be scanned
        assert result["scan"] is not None

    def test_get_stats_default(self):
        """Test stats returns default values when no scans have occurred."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler()
        stats = handler.get_stats()
        assert stats["total_scans"] == 0
        assert stats["clean_scans"] == 0
        assert stats["vulnerable_scans"] == 0
        assert stats["orchestrator_connected"] is False

    @pytest.mark.asyncio
    async def test_pull_request_opened(self):
        """Test pull_request event with 'opened' action."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler()
        payload = {
            "action": "opened",
            "repository": {"full_name": "test/repo"},
            "pull_request": {
                "number": 1,
                "title": "Test PR",
                "user": {"login": "tester"},
                "head": {"ref": "feature-branch", "sha": "def456"},
            },
        }
        result = await handler.handle_webhook("pull_request", payload, {})
        assert result["status"] == "ok"
        assert result["scan"] is not None

    @pytest.mark.asyncio
    async def test_pull_request_closed_ignored(self):
        """Test pull_request event with 'closed' action is ignored."""
        from src.integrations.github_webhook import GitHubWebhookHandler

        handler = GitHubWebhookHandler()
        payload = {
            "action": "closed",
            "repository": {"full_name": "test/repo"},
            "pull_request": {"number": 1},
        }
        result = await handler.handle_webhook("pull_request", payload, {})
        assert result["status"] == "ok"
        assert result["scan"] is None


# ── Slack Bot Tests ──

class TestSlackBot:
    """Test Slack bot slash command handling."""

    @pytest.mark.asyncio
    async def test_analyze_with_orchestrator(self):
        """Test /sentinel-analyze with orchestrator connected."""
        from src.integrations.slack_bot import SlackBot

        bot = SlackBot()
        mock_orc = MagicMock()
        mock_orc.process = AsyncMock(return_value={
            "status": "success",
            "confidence": 0.95,
            "findings": [{"severity": "CRITICAL", "title": "SQL Injection"}],
            "summary": "Found 1 issue",
            "agents_used": ["Code-Scanner"],
            "task_id": "task-1",
        })
        bot.set_orchestrator(mock_orc)

        result = await bot.handle_slash_command(
            "/sentinel-analyze", "eval(user_input)", "user123"
        )
        assert result["response_type"] == "in_channel"
        assert "blocks" in result
        assert result["response_type"] == "in_channel"

    @pytest.mark.asyncio
    async def test_analyze_empty_text(self):
        """Test /sentinel-analyze with no text returns help message."""
        from src.integrations.slack_bot import SlackBot

        bot = SlackBot()
        result = await bot.handle_slash_command(
            "/sentinel-analyze", "", "user123"
        )
        assert "Please provide code" in result.get("text", "")

    @pytest.mark.asyncio
    async def test_status_no_orchestrator(self):
        """Test /sentinel-status returns idle when no orchestrator."""
        from src.integrations.slack_bot import SlackBot

        bot = SlackBot()
        result = await bot.handle_slash_command(
            "/sentinel-status", "", "user123"
        )
        assert "idle" in str(result).lower() or "Status" in str(result)

    @pytest.mark.asyncio
    async def test_help_command(self):
        """Test /sentinel-help returns command list."""
        from src.integrations.slack_bot import SlackBot

        bot = SlackBot()
        result = await bot.handle_slash_command(
            "/sentinel-help", "", "user123"
        )
        assert "blocks" in result
        assert "response_type" in result

    def test_slack_manifest(self):
        """Test Slack App Manifest generation."""
        from src.integrations.slack_bot import SlackBot

        bot = SlackBot()
        manifest = bot.get_slack_manifest()
        assert manifest["display_information"]["name"] == "Sentinel Cyber AI"
        assert len(manifest["features"]["slash_commands"]) == 4
        assert manifest["oauth_config"]["scopes"]["bot"] is not None

    def test_verify_request_no_secret(self):
        """Test request verification skips when no signing secret."""
        from src.integrations.slack_bot import SlackBot

        bot = SlackBot()
        assert bot.verify_request("timestamp", "signature", b"body") is True


# ── Discord Bot Tests ──

class TestDiscordBot:
    """Test Discord bot interaction handling."""

    @pytest.mark.asyncio
    async def test_ping_pong(self):
        """Test PING interaction returns PONG."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        result = await bot.handle_interaction({"type": 1})
        assert result["type"] == 1  # PONG

    @pytest.mark.asyncio
    async def test_analyze_command(self):
        """Test /sentinel analyze command with orchestrator."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        mock_orc = MagicMock()
        mock_orc.process = AsyncMock(return_value={
            "status": "success",
            "confidence": 0.95,
            "findings": [{"severity": "CRITICAL", "title": "SQL Injection"}],
            "summary": "Found 1 issue",
            "agents_used": ["Code-Scanner"],
            "task_id": "task-1",
        })
        bot.set_orchestrator(mock_orc)

        payload = {
            "type": 2,
            "data": {
                "name": "analyze",
                "options": [{"name": "code", "value": "eval(x)"}],
            },
        }
        result = await bot.handle_interaction(payload)
        assert result["type"] == 4  # CHANNEL_MESSAGE_WITH_SOURCE
        assert "embeds" in result["data"]

    @pytest.mark.asyncio
    async def test_unknown_interaction_type(self):
        """Test unknown interaction type returns error message."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        result = await bot.handle_interaction({"type": 99})
        assert "Unknown interaction" in str(result)

    @pytest.mark.asyncio
    async def test_help_command(self):
        """Test /sentinel help returns help embed."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        payload = {
            "type": 2,
            "data": {"name": "help", "options": []},
        }
        result = await bot.handle_interaction(payload)
        assert "Sentinel" in result["data"]["embeds"][0]["title"]

    def test_discord_commands(self):
        """Test Discord slash command definitions."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        commands = bot.get_discord_commands()
        assert len(commands) == 1
        assert commands[0]["name"] == "sentinel"
        assert len(commands[0]["options"]) == 4  # analyze, scan, status, help

    def test_send_alert(self):
        """Test alert embed generation."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        result = bot.send_alert({
            "status": "success",
            "findings": [{"severity": "CRITICAL", "title": "Test vuln"}],
            "summary": "Found issues",
        })
        assert "embeds" in result
        assert result["embeds"][0]["color"] == 0xff0000  # Critical red

    def test_verify_request_no_key(self):
        """Test request verification skips when no public key."""
        from src.integrations.discord_bot import DiscordBot

        bot = DiscordBot()
        assert bot.verify_request("sig", "ts", b"body") is True


# ── Monitoring Integration Tests ──

class TestMonitoringIntegration:
    """Test monitoring system integration with alerting and webhooks."""

    @pytest.mark.asyncio
    async def test_send_alert_console(self):
        """Test sending a console alert."""
        from src.monitoring.monitor import MonitoringSystem, AlertSeverity, AlertChannel

        mon = MonitoringSystem()
        alert = await mon.send_alert(
            title="Test Alert",
            message="This is a test",
            severity=AlertSeverity.INFO,
            source="test",
            channel=AlertChannel.CONSOLE,
        )
        assert alert.title == "Test Alert"
        assert alert.severity == AlertSeverity.INFO
        assert alert.channel == AlertChannel.CONSOLE
        assert alert.acknowledged is False

    @pytest.mark.asyncio
    async def test_acknowledge_alert(self):
        """Test acknowledging an alert."""
        from src.monitoring.monitor import MonitoringSystem, AlertSeverity, AlertChannel

        mon = MonitoringSystem()
        alert = await mon.send_alert("Test", "test", AlertSeverity.WARNING, "test", AlertChannel.CONSOLE)
        assert mon.acknowledge_alert(alert.id) is True
        assert alert.acknowledged is True

    @pytest.mark.asyncio
    async def test_resolve_alert(self):
        """Test resolving an alert."""
        from src.monitoring.monitor import MonitoringSystem, AlertSeverity, AlertChannel

        mon = MonitoringSystem()
        alert = await mon.send_alert("Test", "test", AlertSeverity.ERROR, "test", AlertChannel.CONSOLE)
        assert mon.resolve_alert(alert.id) is True
        assert alert.resolved is True

    def test_track_threat(self):
        """Test threat tracking lifecycle."""
        from src.monitoring.monitor import MonitoringSystem, AlertSeverity

        mon = MonitoringSystem()
        threat = mon.track_threat(
            description="SQL Injection in login endpoint",
            severity=AlertSeverity.CRITICAL,
            source_agent="Code-Scanner",
            affected_files=["src/auth.py"],
            confidence=0.95,
        )
        assert threat.status == "detected"
        assert threat.id in [t.id for t in mon.get_active_threats()]

        # Update to analyzing
        assert mon.update_threat_status(threat.id, "analyzing") is True
        assert threat.status == "analyzing"

        # Resolve
        assert mon.update_threat_status(threat.id, "resolved") is True
        assert threat.id not in mon._active_threats
        assert threat in mon._resolved_threats

    def test_rate_limiting(self):
        """Test rate limiting within and beyond limits."""
        from src.monitoring.monitor import MonitoringSystem

        mon = MonitoringSystem()
        key = "test-client"

        # Should be within limit for first 5 requests
        for _ in range(5):
            assert mon.check_rate_limit(key, max_requests=5, window_seconds=60) is True

        # 6th request should exceed limit
        assert mon.check_rate_limit(key, max_requests=5, window_seconds=60) is False

    def test_metrics_recording(self):
        """Test metric collection and summary."""
        from src.monitoring.monitor import MonitoringSystem

        mon = MonitoringSystem()
        for i in range(10):
            mon.record_metric("test_metric", float(i * 10), {"source": "test"})

        summary = mon.get_metric_summary("test_metric", duration_seconds=3600)
        assert summary["count"] == 10
        assert summary["min"] == 0.0
        assert summary["max"] == 90.0
        assert summary["avg"] == 45.0

    def test_get_metrics_filtered(self):
        """Test metric retrieval with filtering."""
        from src.monitoring.monitor import MonitoringSystem

        mon = MonitoringSystem()
        mon.record_metric("latency_ms", 150.0)
        mon.record_metric("confidence", 0.95)
        mon.record_metric("latency_ms", 200.0)

        latency_metrics = mon.get_metrics(name="latency_ms")
        assert len(latency_metrics) == 2
        assert all(m.name == "latency_ms" for m in latency_metrics)

    def test_dashboard_data(self):
        """Test dashboard data aggregation."""
        from src.monitoring.monitor import MonitoringSystem

        mon = MonitoringSystem()
        data = mon.get_dashboard_data()

        assert "timestamp" in data
        assert "alerts" in data
        assert "active_threats" in data
        assert "metrics" in data
        assert data["alerts"]["stats"]["total"] >= 0


# ── Slack Route Handler Tests ──

class TestSlackRoutes:
    """Test Slack route handler integration."""

    def test_setup_slack_routes_returns_router(self):
        """Test setup_slack_routes returns a configured router."""
        from src.integrations.slack_bot import setup_slack_routes
        from fastapi import APIRouter

        router = APIRouter()
        mock_orc = MagicMock()
        result = setup_slack_routes(router, mock_orc)
        assert result is router

        # Check routes were added
        routes = [r.path for r in router.routes]
        assert "/slack/commands" in routes
        assert "/slack/manifest" in routes
        assert "/slack/webhook" in routes


# ── GitHub Route Handler Tests ──

class TestGitHubRoutes:
    """Test GitHub route handler integration."""

    def test_setup_github_routes_returns_router(self):
        """Test setup_github_routes returns a configured router."""
        from src.integrations.github_webhook import setup_github_routes
        from fastapi import APIRouter

        router = APIRouter()
        mock_orc = MagicMock()
        result = setup_github_routes(router, mock_orc)
        assert result is router

        routes = [r.path for r in router.routes]
        assert "/github/webhook" in routes
        assert "/github/stats" in routes
        assert "/github/scans" in routes
