"""Slack Bot Integration — Sentinel security alerts in your Slack workspace.

Features:
- /sentinel-analyze <code> — Analyze code for vulnerabilities
- /sentinel-scan <repo-url> — Scan a repository
- /sentinel-status — Check system status
- Webhook for automated security alerts

This integrates the multi-agent system directly into your team's workflow.
"""

import logging
import json
import hmac
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Slack Message Templates ──

SLACK_BLOCK_TEMPLATES = {
    "analysis_result": lambda data: {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔐 Sentinel Analysis: {data.get('status', 'Complete').upper()}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Status:*\n{data.get('status', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{data.get('confidence', 0):.0%}"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{len(data.get('findings', []))}"},
                    {"type": "mrkdwn", "text": f"*Agents:*\n{', '.join(data.get('agents_used', ['N/A']))}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:*\n{data.get('summary', 'No summary')}"},
            },
        ]
        + (
            [
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Top Findings:*\n"
                        + "\n".join(
                            f"• *{f.get('severity', 'INFO')}*: {f.get('title', 'Unknown')}"
                            for f in data.get("findings", [])[:5]
                        ),
                    },
                },
            ]
            if data.get("findings")
            else []
        )
        + [
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Sentinel Cyber AI | Task: {data.get('task_id', 'N/A')} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                    }
                ],
            }
        ],
    },
    "error": lambda error_msg: {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "❌ Sentinel Analysis Failed",
                    "emoji": True,
                },
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Error:*\n{error_msg}"}},
        ]
    },
    "status": lambda status_data: {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🟢 Sentinel System Status",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Version:*\n{status_data.get('version', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status_data.get('status', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Agents:*\n{status_data.get('agents', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Analyses:*\n{status_data.get('total_analyses', 0)}"},
                ],
            },
        ]
    },
    "help": lambda: {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🤖 Sentinel Cyber AI — Slack Commands",
                    "emoji": True,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "*/sentinel-analyze <code>* — Analyze code for vulnerabilities\n"
                        "*/sentinel-scan <repo-url>* — Scan a repository (coming soon)\n"
                        "*/sentinel-status* — Check system health\n"
                        "*/sentinel-help* — Show this message\n\n"
                        "Send code in a code block (``` ```) for best results."
                    ),
                },
            },
        ]
    },
}


class SlackBot:
    """Slack bot for Sentinel security alerts and commands."""

    def __init__(self, signing_secret: Optional[str] = None):
        self.signing_secret = signing_secret
        self._orchestrator = None

    def set_orchestrator(self, orchestrator):
        """Set the orchestrator instance for processing queries."""
        self._orchestrator = orchestrator

    def verify_request(self, timestamp: str, signature: str, body: bytes) -> bool:
        """Verify Slack request signature.

        Args:
            timestamp: X-Slack-Request-Timestamp header
            signature: X-Slack-Signature header
            body: Raw request body

        Returns:
            True if signature is valid
        """
        if not self.signing_secret:
            logger.warning("No signing secret configured — skipping verification")
            return True

        import time
        # Prevent replay attacks
        if abs(time.time() - int(timestamp)) > 60 * 5:
            logger.warning("Request timestamp is too old — possible replay attack")
            return False

        sig_basestring = f"v0:{timestamp}:{body.decode('utf-8')}"
        my_signature = "v0=" + hmac.new(
            self.signing_secret.encode(),
            sig_basestring.encode(),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(my_signature, signature)

    async def handle_slash_command(self, command: str, text: str, user_id: str) -> Dict:
        """Handle a Slack slash command.

        Args:
            command: The slash command (e.g., /sentinel-analyze)
            text: The command arguments
            user_id: Slack user ID who invoked the command

        Returns:
            Slack response payload
        """
        command_map = {
            "/sentinel-analyze": self._handle_analyze,
            "/sentinel-scan": self._handle_scan,
            "/sentinel-status": self._handle_status,
            "/sentinel-help": self._handle_help,
        }

        handler = command_map.get(command.lower(), self._handle_help)
        try:
            return await handler(text)
        except Exception as e:
            logger.error(f"Slash command '{command}' failed: {e}")
            return self._error_response(f"Command failed: {str(e)}")

    async def _handle_analyze(self, text: str) -> Dict:
        """Handle /sentinel-analyze command."""
        if not text.strip():
            return self._text_response(
                "Please provide code to analyze. Example:\n"
                "`/sentinel-analyze def login(user):\\n    query = f\\\"SELECT * FROM users WHERE name = '{user}'\\\"`"
            )

        if not self._orchestrator:
            return self._error_response("Sentinel orchestrator not initialized")

        # Defer the response (Slack requires acknowledgment within 3 seconds)
        # Process the analysis
        result = await self._orchestrator.process(text)
        return {
            "response_type": "in_channel",
            "blocks": SLACK_BLOCK_TEMPLATES["analysis_result"](result),
        }

    async def _handle_scan(self, text: str) -> Dict:
        """Handle /sentinel-scan command."""
        if not text.strip():
            return self._text_response(
                "Usage: `/sentinel-scan <repo-url>` — Scan a repository for vulnerabilities\n"
                "Example: `/sentinel-scan https://github.com/user/repo`"
            )

        if not self._orchestrator:
            return self._error_response("Sentinel orchestrator not initialized")

        return self._text_response(
            f"🔄 Scanning repository: {text}\n"
            f"This may take a few minutes. You'll be notified when complete.\n"
            f"(Full repo scanning coming in v2.1)"
        )

    async def _handle_status(self, text: str) -> Dict:
        """Handle /sentinel-status command."""
        if not self._orchestrator:
            return {
                "response_type": "ephemeral",
                "blocks": SLACK_BLOCK_TEMPLATES["status"](
                    {"version": "2.0.0", "status": "idle", "agents": "0", "total_analyses": 0}
                ),
            }

        agents = self._orchestrator.registered_agents
        history = self._orchestrator.get_history(limit=1)

        return {
            "response_type": "ephemeral",
            "blocks": SLACK_BLOCK_TEMPLATES["status"](
                {
                    "version": "2.0.0",
                    "status": "operational",
                    "agents": ", ".join(agents),
                    "total_analyses": len(self._orchestrator._task_history),
                }
            ),
        }

    async def _handle_help(self, text: str = "") -> Dict:
        """Handle /sentinel-help command."""
        return {
            "response_type": "ephemeral",
            "blocks": SLACK_BLOCK_TEMPLATES["help"](),
        }

    def send_alert(self, analysis_result: Dict, channel: str = "#security-alerts") -> Dict:
        """Send an automated security alert to a Slack channel.

        Args:
            analysis_result: Result from orchestrator.process()
            channel: Slack channel to post to

        Returns:
            Slack message payload ready to send via webhook
        """
        return {
            "channel": channel,
            "blocks": SLACK_BLOCK_TEMPLATES["analysis_result"](analysis_result),
        }

    def _text_response(self, text: str) -> Dict:
        """Create a simple text response."""
        return {"response_type": "ephemeral", "text": text}

    def _error_response(self, error_msg: str) -> Dict:
        """Create an error response."""
        return {
            "response_type": "ephemeral",
            "blocks": SLACK_BLOCK_TEMPLATES["error"](error_msg),
        }

    def get_slack_manifest(self) -> Dict:
        """Generate Slack App Manifest for easy setup.

        Returns:
            Slack App Manifest JSON for creating the bot
        """
        return {
            "_metadata": {
                "major_version": 1,
                "minor_version": 1,
            },
            "display_information": {
                "name": "Sentinel Cyber AI",
                "description": "AI-powered security analysis for your team",
                "long_description": (
                    "Sentinel Cyber AI analyzes code for security vulnerabilities, "
                    "generates patches, and provides threat intelligence — all from Slack."
                ),
                "background_color": "#1a1a2e",
            },
            "features": {
                "slash_commands": [
                    {
                        "command": "/sentinel-analyze",
                        "description": "Analyze code for security vulnerabilities",
                        "usage_hint": "[code snippet or description]",
                        "should_escape": True,
                    },
                    {
                        "command": "/sentinel-scan",
                        "description": "Scan a repository for vulnerabilities",
                        "usage_hint": "[repository URL]",
                        "should_escape": False,
                    },
                    {
                        "command": "/sentinel-status",
                        "description": "Check Sentinel system status",
                        "usage_hint": "",
                        "should_escape": False,
                    },
                    {
                        "command": "/sentinel-help",
                        "description": "Show available commands",
                        "usage_hint": "",
                        "should_escape": False,
                    },
                ],
            },
            "oauth_config": {
                "scopes": {
                    "bot": [
                        "commands",
                        "chat:write",
                        "chat:write.public",
                        "channels:read",
                    ]
                }
            },
            "settings": {
                "interactivity": {"is_enabled": True, "request_url": "https://your-server.com/slack/commands"},
                "org_deploy_enabled": False,
                "socket_mode_enabled": False,
                "token_rotation_enabled": False,
            },
        }


def setup_slack_routes(router, orchestrator):
    """Add Slack webhook endpoints to the FastAPI router.

    Args:
        router: FastAPI APIRouter
        orchestrator: The Sentinel orchestrator instance
    """
    from fastapi import Request, HTTPException

    bot = SlackBot()
    bot.set_orchestrator(orchestrator)

    @router.post("/slack/commands")
    async def slack_commands(request: Request):
        """Handle Slack slash commands."""
        form = await request.form()
        command = form.get("command", "")
        text = form.get("text", "")
        user_id = form.get("user_id", "")

        # Verify signature in production
        # timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
        # signature = request.headers.get("X-Slack-Signature", "")
        # body = await request.body()
        # if not bot.verify_request(timestamp, signature, body):
        #     raise HTTPException(status_code=403, detail="Invalid signature")

        result = await bot.handle_slash_command(command, text, user_id)
        return result

    @router.get("/slack/manifest")
    async def slack_manifest():
        """Get the Slack App Manifest for easy setup."""
        return bot.get_slack_manifest()

    @router.post("/slack/webhook")
    async def slack_webhook(payload: Dict):
        """Receive Slack webhook events."""
        # Handle Slack events (message actions, etc.)
        challenge = payload.get("challenge")
        if challenge:
            return {"challenge": challenge}

        event = payload.get("event", {})
        if event.get("type") == "message" and not event.get("bot_id"):
            # Auto-analyze code sent in DMs to the bot
            text = event.get("text", "")
            if "```" in text:
                result = await orchestrator.process(text)
                return bot.send_alert(result)

        return {"ok": True}

    return router
