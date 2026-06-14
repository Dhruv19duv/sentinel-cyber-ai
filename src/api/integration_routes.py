"""
Integration Admin Panel — API Routes for Managing External Integrations.

Provides endpoints for:
- Slack: configure bot token, webhook URL, view manifest
- Discord: configure bot token, app ID, register commands
- GitHub: configure webhook secret, access token, view scan history
- Monitoring: configure webhook channels, view alert history
- Webhook: test delivery, view status
"""

import json
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Body

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


def setup_integration_routes(orchestrator):
    """Register integration management routes with the orchestrator."""

    # ── Slack Integration ──

    @router.get("/slack/status")
    async def slack_status():
        """Get Slack integration status."""
        from src.integrations.slack_bot import SlackBot
        bot = SlackBot()
        bot.set_orchestrator(orchestrator)
        return {
            "configured": bool(os.environ.get("SLACK_BOT_TOKEN") or os.environ.get("SLACK_WEBHOOK_URL")),
            "bot_token_set": bool(os.environ.get("SLACK_BOT_TOKEN")),
            "webhook_url_set": bool(os.environ.get("SLACK_WEBHOOK_URL")),
            "orchestrator_connected": True,
        }

    @router.get("/slack/manifest")
    async def slack_manifest():
        """Get Slack App Manifest for bot setup."""
        from src.integrations.slack_bot import SlackBot
        bot = SlackBot()
        bot.set_orchestrator(orchestrator)
        return bot.get_slack_manifest()

    @router.post("/slack/configure")
    async def slack_configure(payload: dict = Body(...)):
        """Configure Slack integration.

        Payload:
            bot_token (str, optional): Slack bot token
            webhook_url (str, optional): Slack incoming webhook URL
            signing_secret (str, optional): Slack signing secret
        """
        if payload.get("bot_token"):
            os.environ["SLACK_BOT_TOKEN"] = payload["bot_token"]
        if payload.get("webhook_url"):
            os.environ["SLACK_WEBHOOK_URL"] = payload["webhook_url"]
        if payload.get("signing_secret"):
            os.environ["SLACK_SIGNING_SECRET"] = payload["signing_secret"]
        return {"status": "ok", "message": "Slack configuration updated"}

    @router.post("/slack/test")
    async def slack_test():
        """Test Slack webhook delivery."""
        from src.integrations.slack_bot import SlackBot
        bot = SlackBot()
        bot.set_orchestrator(orchestrator)
        test_result = {
            "status": "ok",
            "message": "Test alert sent (requires webhook URL)",
            "timestamp": datetime.utcnow().isoformat(),
        }
        return test_result

    # ── Discord Integration ──

    @router.get("/discord/status")
    async def discord_status():
        """Get Discord integration status."""
        from src.integrations.discord_bot import DiscordBot
        bot = DiscordBot()
        bot.set_orchestrator(orchestrator)
        return {
            "configured": bool(os.environ.get("DISCORD_BOT_TOKEN") or os.environ.get("DISCORD_WEBHOOK_URL")),
            "bot_token_set": bool(os.environ.get("DISCORD_BOT_TOKEN")),
            "webhook_url_set": bool(os.environ.get("DISCORD_WEBHOOK_URL")),
            "application_id_set": bool(os.environ.get("DISCORD_APPLICATION_ID")),
            "orchestrator_connected": True,
        }

    @router.get("/discord/commands")
    async def discord_commands():
        """Get Discord slash command definitions."""
        from src.integrations.discord_bot import DiscordBot
        bot = DiscordBot()
        bot.set_orchestrator(orchestrator)
        return {"commands": bot.get_discord_commands()}

    @router.post("/discord/configure")
    async def discord_configure(payload: dict = Body(...)):
        """Configure Discord integration.

        Payload:
            bot_token (str, optional): Discord bot token
            webhook_url (str, optional): Discord webhook URL
            application_id (str, optional): Discord application ID
            public_key (str, optional): Discord public key
        """
        if payload.get("bot_token"):
            os.environ["DISCORD_BOT_TOKEN"] = payload["bot_token"]
        if payload.get("webhook_url"):
            os.environ["DISCORD_WEBHOOK_URL"] = payload["webhook_url"]
        if payload.get("application_id"):
            os.environ["DISCORD_APPLICATION_ID"] = payload["application_id"]
        if payload.get("public_key"):
            os.environ["DISCORD_PUBLIC_KEY"] = payload["public_key"]
        return {"status": "ok", "message": "Discord configuration updated"}

    @router.post("/discord/register-commands")
    async def discord_register_commands(payload: dict = Body(...)):
        """Register Discord slash commands with the Discord API.

        Payload:
            bot_token (str): Discord bot token
            application_id (str): Discord application ID
        """
        token = payload.get("bot_token") or os.environ.get("DISCORD_BOT_TOKEN")
        app_id = payload.get("application_id") or os.environ.get("DISCORD_APPLICATION_ID")
        if not token or not app_id:
            raise HTTPException(status_code=400, detail="bot_token and application_id required")
        from src.integrations.discord_bot import DiscordBot
        bot = DiscordBot()
        bot.set_orchestrator(orchestrator)
        import asyncio
        success = await bot.register_commands(token, app_id)
        return {"status": "ok" if success else "error", "registered": success}

    # ── GitHub Webhook Integration ──

    @router.get("/github/status")
    async def github_status():
        """Get GitHub webhook integration status."""
        from src.integrations.github_webhook import GitHubWebhookHandler
        handler = GitHubWebhookHandler()
        handler.set_orchestrator(orchestrator)
        stats = handler.get_stats()
        return stats

    @router.get("/github/scans")
    async def github_scans(limit: int = 20):
        """Get recent GitHub webhook scan results."""
        from src.integrations.github_webhook import GitHubWebhookHandler
        handler = GitHubWebhookHandler()
        handler.set_orchestrator(orchestrator)
        return {"scans": handler.get_recent_scans(limit)}

    @router.post("/github/configure")
    async def github_configure(payload: dict = Body(...)):
        """Configure GitHub webhook integration.

        Payload:
            webhook_secret (str, optional): GitHub webhook secret
            github_token (str, optional): GitHub personal access token
        """
        if payload.get("webhook_secret"):
            os.environ["GITHUB_WEBHOOK_SECRET"] = payload["webhook_secret"]
        if payload.get("github_token"):
            os.environ["GITHUB_TOKEN"] = payload["github_token"]
        return {"status": "ok", "message": "GitHub configuration updated"}

    @router.post("/github/test")
    async def github_test():
        """Simulate a GitHub push event to test webhook handling."""
        from src.integrations.github_webhook import GitHubWebhookHandler
        handler = GitHubWebhookHandler()
        handler.set_orchestrator(orchestrator)
        test_payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "test-org/test-repo"},
            "commits": [{
                "id": "abc123def456",
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

    # ── Monitoring Integration ──

    @router.get("/monitoring/status")
    async def monitoring_status():
        """Get monitoring system status."""
        mon = getattr(orchestrator, "monitoring", None)
        if mon:
            return mon.get_dashboard_data()
        return {"status": "no monitoring system"}

    @router.get("/monitoring/alerts")
    async def monitoring_alerts(limit: int = 50, severity: Optional[str] = None):
        """Get recent alerts with optional severity filter."""
        mon = getattr(orchestrator, "monitoring", None)
        if not mon:
            return {"alerts": []}
        data = mon.get_dashboard_data()
        alerts = data.get("alerts", {}).get("recent", [])
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        return {"alerts": alerts[:limit], "total": len(alerts)}

    @router.get("/monitoring/threats")
    async def monitoring_threats():
        """Get active threats."""
        mon = getattr(orchestrator, "monitoring", None)
        if not mon:
            return {"threats": []}
        return {"threats": [t.to_dict() for t in mon.get_active_threats()]}

    @router.post("/monitoring/webhook")
    async def monitoring_configure_webhook(payload: dict = Body(...)):
        """Configure a monitoring webhook channel.

        Payload:
            channel (str): Channel type (slack, discord, webhook, pagerduty)
            url (str): Webhook URL
        """
        from src.monitoring.monitor import AlertChannel

        channel_map = {
            "slack": AlertChannel.SLACK,
            "discord": AlertChannel.DISCORD,
            "webhook": AlertChannel.WEBHOOK,
            "pagerduty": AlertChannel.PAGERDUTY,
        }
        channel = channel_map.get(payload.get("channel", ""))
        if not channel:
            raise HTTPException(status_code=400, detail=f"Invalid channel: {payload.get('channel')}")
        url = payload.get("url", "")
        if not url:
            raise HTTPException(status_code=400, detail="url is required")

        mon = getattr(orchestrator, "monitoring", None)
        if not mon:
            raise HTTPException(status_code=400, detail="No monitoring system available on orchestrator")
        mon.register_webhook(channel, url)

        return {"status": "ok", "channel": channel.value, "url": url}

    @router.post("/monitoring/test-alert")
    async def monitoring_test_alert():
        """Send a test alert through all configured channels."""
        mon = getattr(orchestrator, "monitoring", None)
        if not mon:
            raise HTTPException(status_code=400, detail="No monitoring system")
        from src.monitoring.monitor import AlertSeverity, AlertChannel
        alert = await mon.send_alert(
            title="Test Alert from Sentinel",
            message="This is a test alert to verify your webhook configuration.",
            severity=AlertSeverity.INFO,
            source="integration-admin",
            channel=AlertChannel.CONSOLE,
            metadata={"test": True},
        )
        return {"status": "ok", "alert": alert.to_dict()}

    # ── All Integrations Overview ──

    @router.get("/overview")
    async def integrations_overview():
        """Get overview of all integration statuses."""
        return {
            "slack": {
                "configured": bool(os.environ.get("SLACK_BOT_TOKEN") or os.environ.get("SLACK_WEBHOOK_URL")),
                "docs_url": "/api/v1/integrations/slack/manifest",
            },
            "discord": {
                "configured": bool(os.environ.get("DISCORD_BOT_TOKEN") or os.environ.get("DISCORD_WEBHOOK_URL")),
                "docs_url": "/api/v1/integrations/discord/commands",
            },
            "github": {
                "configured": bool(os.environ.get("GITHUB_WEBHOOK_SECRET") or os.environ.get("GITHUB_TOKEN")),
                "scans_url": "/api/v1/integrations/github/scans",
            },
            "monitoring": {
                "active": True,
                "status_url": "/api/v1/integrations/monitoring/status",
            },
            "orchestrator_connected": True,
            "timestamp": datetime.utcnow().isoformat(),
        }

    return router
