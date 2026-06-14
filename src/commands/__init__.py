"""Slash Command System — Ported from Anthropic Claude Code's leaked source.

Commands are registered in a central registry and dispatched by type:
- PromptCommand: Sends a structured prompt to an agent with relevant tools
- LocalCommand: Runs in-process, returns plain text
- LocalJSXCommand: Runs in-process, renders rich terminal UI

This follows the same architecture as Claude Code's src/commands/ system.
"""

from src.commands.base import (
    Command,
    CommandType,
    CommandRegistry,
    PromptCommand,
    LocalCommand,
    LocalJSXCommand,
    CommandResult,
)

__all__ = [
    "Command", "CommandType", "CommandRegistry",
    "PromptCommand", "LocalCommand", "LocalJSXCommand", "CommandResult",
]
