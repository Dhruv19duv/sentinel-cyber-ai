"""
Memory Slash Commands — Ported from Claude Code's CLAUDE.md memory system.

Commands:
  /memory       — View and manage persistent memory (CLAUDE.md equivalent)
  /memory set   — Set memory values (key=value)
  /memory show  — Show all memory entries
  /memory clear — Clear memory
"""

import time
import os
from typing import Optional, Dict, Any

from src.commands.base import (
    Command, CommandResult, CommandType,
    LocalCommand,
)

# ── /memory handlers ──

async def _cmd_memory(args: str, orchestrator=None, context=None) -> CommandResult:
    """View and manage persistent memory."""
    start = time.time()
    args = args.strip().lower()

    if not orchestrator:
        return CommandResult(
            success=False,
            output="Memory management requires the orchestrator.",
            error="No orchestrator",
        )

    memory = orchestrator.memory

    if not args or args == "status":
        status = memory.get_status()
        lines = ["📝 Memory Status:", ""]
        for key, value in status.items():
            if isinstance(value, dict):
                lines.append(f"  {key}:")
                for k, v in value.items():
                    lines.append(f"    {k}: {v}")
            else:
                lines.append(f"  {key}: {value}")

        # Show compressed context
        ctx = memory.get_compressed_context()
        if ctx:
            lines.append(f"\n  Compressed Context ({len(ctx.split())} words):")
            lines.append(f"  {ctx[:500]}...")

        return CommandResult(
            success=True,
            output="\n".join(lines),
            data={"status": status},
            duration_ms=(time.time() - start) * 1000,
        )

    elif args.startswith("set "):
        content = args[4:].strip()
        if not content:
            return CommandResult(success=False, output="Usage: /memory set <content>")

        # Check for key=value format
        if "=" in content:
            key, value = content.split("=", 1)
            memory.add_project_entry(f"{key.strip()}: {value.strip()}", tags=["memory", "key-value"])
            return CommandResult(
                success=True,
                output=f"✅ Set memory: {key.strip()} = {value.strip()}",
            )
        else:
            memory.add_project_entry(content, tags=["memory", "manual"])
            return CommandResult(
                success=True,
                output=f"✅ Added to memory: {content[:100]}...",
            )

    elif args == "show":
        ctx = memory.get_compressed_context()
        if ctx:
            return CommandResult(success=True, output=f"📝 Memory:\n\n{ctx}")
        return CommandResult(success=True, output="📝 Memory is empty.")

    elif args == "clear":
        # Clear session memory — preserves system and project memory
        memory.clear_session()
        return CommandResult(success=True, output="Session memory cleared. System and project memory preserved.")

    elif args == "compact":
        import asyncio
        result = await memory.compact_async()
        lines = ["✅ Memory compacted:", ""]
        for k, v in result.items():
            lines.append(f"  {k}: {v}")
        return CommandResult(
            success=True,
            output="\n".join(lines),
            data={"compaction": result},
        )

    else:
        return CommandResult(
            success=False,
            output=f"Unknown subcommand: {args}\n"
                   f"Usage: /memory [status|set <text>|show|clear|compact]",
        )


memory_command = LocalCommand(
    name="memory",
    description="View and manage persistent memory (CLAUDE.md equivalent)",
    handler=_cmd_memory,
    aliases=["mem", "remember", "claude.md"],
)
