"""
Help Slash Commands — Ported from Claude Code's help system.

Commands:
  /help       — Show help for all commands or a specific command
  /?          — Alias for /help
"""

import time
from typing import Optional, Dict, Any

from src.commands.base import (
    Command, CommandResult, CommandType,
    LocalCommand,
)


async def _cmd_help(args: str, orchestrator=None, context=None) -> CommandResult:
    """Show help information."""
    start = time.time()
    args = args.strip().lower()

    if orchestrator and hasattr(orchestrator, 'command_registry'):
        registry = orchestrator.command_registry

        if args:
            # Show help for a specific command
            cmd = registry.get(args)
            if cmd:
                lines = [
                    f"📖 /{cmd.name}",
                    f"  {cmd.description}",
                    f"  Type: {cmd.command_type.value}",
                ]
                if cmd.aliases:
                    lines.append(f"  Aliases: {', '.join(cmd.aliases)}")
                if cmd.permission_scope:
                    lines.append(f"  Permission: {cmd.permission_scope}")
                return CommandResult(
                    success=True,
                    output="\n".join(lines),
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                return CommandResult(
                    success=False,
                    output=f"Unknown command: /{args}. Try /help for a list.",
                )

        # Show all commands
        help_text = registry.get_help_text()
        return CommandResult(
            success=True,
            output=help_text,
            duration_ms=(time.time() - start) * 1000,
        )

    # Fallback if no registry
    return CommandResult(
        success=True,
        output=(
            "Available commands:\n"
            "  /help, /?, /review, /security-review, /bughunter,\n"
            "  /commit, /commit-push-pr, /branch, /diff, /rewind,\n"
            "  /memory, /config, /model, /permissions,\n"
            "  /doctor, /cost, /version, /stats\n"
        ),
        duration_ms=(time.time() - start) * 1000,
    )


help_command = LocalCommand(
    name="help",
    description="Show help for all commands or a specific command",
    handler=_cmd_help,
    aliases=["?", "h", "man", "commands"],
)
