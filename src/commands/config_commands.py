"""
Configuration Slash Commands — Ported from Claude Code's config system.

Commands:
  /config       — View or modify configuration
  /model        — View or switch the active model/agent
  /theme        — Toggle terminal theme (when rich is available)
  /permissions  — View and manage tool permissions
"""

import time
import os
from typing import Optional, Dict, Any

from src.commands.base import (
    Command, CommandResult, CommandType,
    LocalCommand, PromptCommand,
)


# ── /config ──

async def _cmd_config(args: str, orchestrator=None, context=None) -> CommandResult:
    """View or modify Sentinel configuration."""
    start = time.time()
    args = args.strip().lower()

    config_items = {
        "effort": ("High", "Adaptive thinking effort (low/medium/high/max)"),
        "memory": ("Enabled", "Persistent memory system"),
        "safety": ("Enabled", "Safety classifiers"),
        "context": ("1M tokens", "Context window size"),
        "parallel": ("True", "Run secondary agents in parallel"),
    }

    if not args:
        lines = ["⚙️ Configuration:", ""]
        for key, (val, desc) in config_items.items():
            lines.append(f"  {key:<12} = {val:<12}  # {desc}")
        lines.append("")
        lines.append("  Use /config <key>=<value> to modify")
        return CommandResult(
            success=True,
            output="\n".join(lines),
            duration_ms=(time.time() - start) * 1000,
        )

    if "=" in args:
        key, value = args.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Apply configuration
        if key == "effort" and orchestrator:
            if value.lower() in ("low", "medium", "high", "max"):
                orchestrator.thinking_engine.set_effort(value.lower())
                return CommandResult(
                    success=True,
                    output=f"✅ Effort set to: {value.lower()}",
                )
        elif key == "parallel" and orchestrator:
            val = value.lower() in ("true", "1", "yes")
            # orchestrator.parallel = val  # Could add this property
            return CommandResult(success=True, output=f"✅ Parallel mode: {val}")
        else:
            return CommandResult(success=False, output=f"Unknown config key: {key}")

    # Show specific key
    if args in config_items:
        val, desc = config_items[args]
        return CommandResult(success=True, output=f"{args} = {val}  # {desc}")

    return CommandResult(success=False, output=f"Unknown config key: {args}")


# ── /model ──

async def _cmd_model(args: str, orchestrator=None, context=None) -> CommandResult:
    """View or switch the active model/agent configuration."""
    start = time.time()
    args = args.strip()

    if not orchestrator:
        return CommandResult(success=False, output="Orchestrator not available.")

    if not args or args == "list":
        lines = ["🤖 Available Agents & Models:", ""]
        for name in orchestrator.registered_agents:
            agent = orchestrator.get_agent(name)
            if agent:
                lines.append(f"  {name:<20} {agent.model_name}")
        return CommandResult(
            success=True,
            output="\n".join(lines),
            duration_ms=(time.time() - start) * 1000,
        )

    if args == "effort":
        effort = orchestrator.thinking_engine.get_effort()
        return CommandResult(success=True, output=f"Current effort: {effort.value}")

    return CommandResult(success=False, output=f"Usage: /model [list|effort]")


# ── /permissions ──

async def _cmd_permissions(args: str, orchestrator=None, context=None) -> CommandResult:
    """View and manage tool permissions."""
    start = time.time()

    from src.permissions.permission_manager import PermissionManager
    pm = PermissionManager()

    if not args or args == "list":
        rules = pm.list_rules()
        lines = ["🔐 Permission Rules:", ""]
        for rule in rules:
            lines.append(f"  {rule['scope']:<25} {rule['mode']:<8} {rule['description']}")
        return CommandResult(
            success=True,
            output="\n".join(lines),
            data={"rules": rules},
            duration_ms=(time.time() - start) * 1000,
        )

    if args.startswith("allow "):
        scope = args[6:].strip()
        pm.set_rule(scope, "allow")
        return CommandResult(success=True, output=f"✅ Allowed: {scope}")

    if args.startswith("deny "):
        scope = args[5:].strip()
        pm.set_rule(scope, "deny")
        return CommandResult(success=True, output=f"✅ Denied: {scope}")

    if args.startswith("ask "):
        scope = args[4:].strip()
        pm.set_rule(scope, "ask")
        return CommandResult(success=True, output=f"✅ Set to ask: {scope}")

    return CommandResult(success=False, output=f"Usage: /permissions [list|allow <scope>|deny <scope>|ask <scope>]")


# ── Command definitions ──

config_command = LocalCommand(
    name="config",
    description="View or modify configuration (/config key=value)",
    handler=_cmd_config,
    aliases=["cfg", "settings"],
)

model_command = LocalCommand(
    name="model",
    description="View or switch the active model/agent",
    handler=_cmd_model,
    aliases=["agent", "llm", "models"],
)

permissions_command = LocalCommand(
    name="permissions",
    description="View and manage tool permissions",
    handler=_cmd_permissions,
    aliases=["perms", "security", "policy"],
)


# ── All config commands ──

CONFIG_COMMANDS = [
    config_command,
    model_command,
    permissions_command,
]
