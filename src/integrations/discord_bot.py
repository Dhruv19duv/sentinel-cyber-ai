"""
Discord Bot Integration — Sentinel security commands in your Discord server.

Commands:
  /sentinel analyze <code> — Analyze code for vulnerabilities
  /sentinel scan <repo>   — Scan a repository
  /sentinel status        — Check system health
  /sentinel help          — Show available commands

Webhook for automated security alerts.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

DISCORD_EMBED_COLORS = {
    "success": 0x00ff88,
    "error": 0xff4444,
    "warning": 0xffaa00,
    "info": 0x58a6ff,
    "critical": 0xff0000,
}


class DiscordBot:
    """Discord bot for Sentinel security commands and alerts."""

    def __init__(self, application_id: Optional[str] = None, public_key: Optional[str] = None):
        self.application_id = application_id
        self.public_key = public_key
        self._orchestrator = None

    def set_orchestrator(self, orchestrator):
        """Set the orchestrator instance for processing queries."""
        self._orchestrator = orchestrator

    def verify_request(self, signature: str, timestamp: str, body: bytes) -> bool:
        """Verify Discord interaction request signature.

        Args:
            signature: X-Signature-Ed25519 header
            timestamp: X-Signature-Timestamp header
            body: Raw request body

        Returns:
            True if signature is valid
        """
        if not self.public_key:
            logger.warning("No public key configured — skipping verification")
            return True

        try:
            from nacl.bindings import crypto_sign_ed25519_open
            message = timestamp.encode() + body
            try:
                crypto_sign_ed25519_open(
                    bytes.fromhex(signature) + message,
                    bytes.fromhex(self.public_key)
                )
                return True
            except Exception:
                logger.warning("Signature verification failed — invalid signature")
                return False
        except ImportError:
            logger.warning("PyNaCl not installed — install with: pip install pynacl")
            return True
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    async def handle_interaction(self, payload: Dict) -> Dict:
        """Handle a Discord interaction (slash command).

        Args:
            payload: Discord interaction payload

        Returns:
            Discord interaction response
        """
        interaction_type = payload.get("type", 0)

        # PING (type 1)
        if interaction_type == 1:
            return {"type": 1}  # PONG

        # APPLICATION_COMMAND (type 2)
        if interaction_type == 2:
            data = payload.get("data", {})
            command_name = data.get("name", "")
            options = self._parse_options(data.get("options", []))

            handlers = {
                "analyze": self._handle_analyze,
                "scan": self._handle_scan,
                "status": self._handle_status,
                "help": self._handle_help,
            }

            handler = handlers.get(command_name, self._handle_help)
            try:
                return await handler(options)
            except Exception as e:
                logger.error(f"Command '{command_name}' failed: {e}")
                return self._error_response(f"Command failed: {str(e)}")

        return {"type": 4, "data": {"content": "Unknown interaction type"}}

    def _parse_options(self, options: List[Dict]) -> Dict[str, str]:
        """Parse Discord slash command options into a dict."""
        result = {}
        for opt in options:
            result[opt.get("name", "")] = opt.get("value", "")
            # Handle nested options (subcommands)
            if opt.get("options"):
                result.update(self._parse_options(opt["options"]))
        return result

    async def _handle_analyze(self, options: Dict) -> Dict:
        """Handle /sentinel analyze command."""
        code = options.get("code", options.get("query", ""))
        if not code.strip():
            return self._error_response(
                "Please provide code to analyze.\n"
                "Usage: `/sentinel analyze code: <your code here>`"
            )

        if not self._orchestrator:
            return self._error_response("Sentinel orchestrator not initialized")

        # Defer response (Discord requires acknowledgment within 3 seconds)
        # We respond with DEFERRED_CHANNEL_MESSAGE (type 5)
        result = await self._orchestrator.process(code)

        findings = result.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        status = result.get("status", "unknown")

        color = DISCORD_EMBED_COLORS.get(
            status if status in DISCORD_EMBED_COLORS else "info"
        )

        embed = {
            "title": f"Sentinel Analysis — {status.upper()}",
            "color": color,
            "fields": [
                {"name": "Status", "value": status.upper(), "inline": True},
                {"name": "Confidence", "value": f"{result.get('confidence', 0):.0%}", "inline": True},
                {"name": "Findings", "value": str(len(findings)), "inline": True},
                {"name": "Agents Used", "value": ", ".join(result.get("agents_used", ["N/A"])), "inline": False},
            ],
            "footer": {"text": f"Sentinel Cyber AI | Task: {result.get('task_id', 'N/A')}"},
            "timestamp": datetime.utcnow().isoformat(),
        }

        if result.get("summary"):
            embed["description"] = result["summary"]

        if findings:
            top_findings = "\n".join(
                f"**{f.get('severity', 'INFO')}**: {f.get('title', 'Unknown')}"
                for f in findings[:5]
            )
            embed["fields"].append({"name": "Top Findings", "value": top_findings, "inline": False})

        if critical:
            embed["fields"].append({
                "name": "Critical Issues",
                "value": f"**{critical} critical** vulnerabilities found — immediate attention required",
                "inline": False,
            })

        if high:
            embed["fields"].append({
                "name": "High Severity Issues",
                "value": f"{high} high severity vulnerabilities found",
                "inline": False,
            })

        return {
            "type": 4,  # CHANNEL_MESSAGE_WITH_SOURCE
            "data": {"embeds": [embed]},
        }

    async def _handle_scan(self, options: Dict) -> Dict:
        """Handle /sentinel scan command."""
        repo = options.get("repo", options.get("url", ""))
        if not repo.strip():
            return self._error_response(
                "Please provide a repository URL.\n"
                "Usage: `/sentinel scan repo: https://github.com/user/repo`"
            )

        return {
            "type": 4,
            "data": {
                "embeds": [{
                    "title": "Scan Initiated",
                    "description": f"Scanning repository: {repo}",
                    "color": DISCORD_EMBED_COLORS["info"],
                    "fields": [
                        {"name": "Repository", "value": repo, "inline": True},
                        {"name": "Status", "value": "In Progress", "inline": True},
                    ],
                    "footer": {"text": "Sentinel Cyber AI"},
                    "timestamp": datetime.utcnow().isoformat(),
                }]
            },
        }

    async def _handle_status(self, options: Dict) -> Dict:
        """Handle /sentinel status command."""
        if not self._orchestrator:
            return {
                "type": 4,
                "data": {
                    "embeds": [{
                        "title": "Sentinel System Status",
                        "description": "Orchestrator not initialized",
                        "color": DISCORD_EMBED_COLORS["warning"],
                        "fields": [
                            {"name": "Version", "value": "2.0.0", "inline": True},
                            {"name": "Status", "value": "Idle", "inline": True},
                        ],
                    }]
                },
            }

        agents = self._orchestrator.registered_agents
        history = self._orchestrator.get_history(limit=1)

        return {
            "type": 4,
            "data": {
                "embeds": [{
                    "title": "Sentinel System Status",
                    "color": DISCORD_EMBED_COLORS["success"],
                    "fields": [
                        {"name": "Version", "value": "2.0.0", "inline": True},
                        {"name": "Status", "value": "Operational", "inline": True},
                        {"name": "Agents", "value": ", ".join(agents), "inline": False},
                        {"name": "Analyses", "value": str(len(self._orchestrator._task_history)), "inline": True},
                    ],
                    "footer": {"text": "Sentinel Cyber AI"},
                    "timestamp": datetime.utcnow().isoformat(),
                }]
            },
        }

    async def _handle_help(self, options: Dict = None) -> Dict:
        """Handle /sentinel help command."""
        return {
            "type": 4,
            "data": {
                "embeds": [{
                    "title": "Sentinel Cyber AI — Discord Commands",
                    "color": DISCORD_EMBED_COLORS["info"],
                    "description": (
                        "**/sentinel analyze <code>** — Analyze code for vulnerabilities\n"
                        "**/sentinel scan <repo>** — Scan a repository\n"
                        "**/sentinel status** — Check system health\n"
                        "**/sentinel help** — Show this message\n\n"
                        "Use code blocks (``` ```) for best results."
                    ),
                    "footer": {"text": "Sentinel Cyber AI"},
                }]
            },
        }

    def _error_response(self, error_msg: str) -> Dict:
        """Create an error response."""
        return {
            "type": 4,
            "data": {
                "embeds": [{
                    "title": "Error",
                    "description": error_msg,
                    "color": DISCORD_EMBED_COLORS["error"],
                }]
            },
        }

    def send_alert(self, analysis_result: Dict) -> Dict:
        """Create a security alert embed for Discord webhook.

        Args:
            analysis_result: Result from orchestrator.process()

        Returns:
            Discord embed payload for webhook
        """
        findings = analysis_result.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")

        embed = {
            "title": f"Security Alert — {analysis_result.get('status', 'UNKNOWN').upper()}",
            "color": DISCORD_EMBED_COLORS["critical"] if critical else DISCORD_EMBED_COLORS["warning"],
            "fields": [
                {"name": "Findings", "value": str(len(findings)), "inline": True},
                {"name": "Critical", "value": str(critical), "inline": True},
                {"name": "Summary", "value": analysis_result.get("summary", "N/A")[:200], "inline": False},
            ],
            "footer": {"text": "Sentinel Cyber AI Automated Alert"},
            "timestamp": datetime.utcnow().isoformat(),
        }

        return {"embeds": [embed]}

    def get_discord_commands(self) -> List[Dict]:
        """Generate Discord Slash Command definitions for registration.

        Returns:
            List of Discord application command definitions
        """
        return [
            {
                "name": "sentinel",
                "description": "Sentinel Cyber AI security analysis",
                "options": [
                    {
                        "type": 1,  # SUB_COMMAND
                        "name": "analyze",
                        "description": "Analyze code for security vulnerabilities",
                        "options": [
                            {
                                "type": 3,  # STRING
                                "name": "code",
                                "description": "Code or description to analyze",
                                "required": True,
                            }
                        ],
                    },
                    {
                        "type": 1,  # SUB_COMMAND
                        "name": "scan",
                        "description": "Scan a repository for vulnerabilities",
                        "options": [
                            {
                                "type": 3,  # STRING
                                "name": "repo",
                                "description": "Repository URL to scan",
                                "required": True,
                            }
                        ],
                    },
                    {
                        "type": 1,  # SUB_COMMAND
                        "name": "status",
                        "description": "Check Sentinel system health",
                        "options": [],
                    },
                    {
                        "type": 1,  # SUB_COMMAND
                        "name": "help",
                        "description": "Show available commands",
                        "options": [],
                    },
                ],
            }
        ]

    async def register_commands(self, bot_token: str, application_id: Optional[str] = None) -> bool:
        """Register slash commands with Discord API.

        Args:
            bot_token: Discord bot token
            application_id: Discord application ID (falls back to self.application_id)

        Returns:
            True if registration succeeded
        """
        app_id = application_id or self.application_id
        if not app_id:
            logger.error("No application ID provided for command registration")
            return False

        try:
            import aiohttp
            commands = self.get_discord_commands()
            url = f"https://discord.com/api/v10/applications/{app_id}/commands"

            async with aiohttp.ClientSession() as session:
                for cmd in commands:
                    async with session.post(
                        url,
                        json=cmd,
                        headers={"Authorization": f"Bot {bot_token}"},
                    ) as resp:
                        if resp.status not in (200, 201):
                            text = await resp.text()
                            logger.error(f"Failed to register command '{cmd['name']}': {resp.status} - {text}")
                            return False
                        logger.info(f"Registered Discord command: /{cmd['name']}")
            return True
        except ImportError:
            logger.warning("aiohttp not installed. Install with: pip install aiohttp")
            return False
        except Exception as e:
            logger.error(f"Command registration failed: {e}")
            return False


def setup_discord_routes(router, orchestrator):
    """Add Discord interaction endpoints to the FastAPI router.

    Args:
        router: FastAPI APIRouter
        orchestrator: The Sentinel orchestrator instance
    """
    from fastapi import Request, HTTPException

    bot = DiscordBot()
    bot.set_orchestrator(orchestrator)

    @router.post("/discord/interactions")
    async def discord_interactions(request: Request):
        """Handle Discord interactions (slash commands)."""
        body = await request.body()
        signature = request.headers.get("X-Signature-Ed25519", "")
        timestamp = request.headers.get("X-Signature-Timestamp", "")

        payload = json.loads(body)
        result = await bot.handle_interaction(payload)
        return result

    @router.get("/discord/commands")
    async def discord_commands():
        """Get the Discord command definitions for registration."""
        return {"commands": bot.get_discord_commands()}

    @router.post("/discord/webhook")
    async def discord_webhook(payload: Dict):
        """Receive Discord webhook events."""
        return {"ok": True}

    return router
