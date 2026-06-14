"""
Base Command System — Ported from Anthropic Claude Code's leaked source.

Architecture matches Claude Code's src/commands/ system:
- Command interface with type, name, description
- Three command types: PromptCommand, LocalCommand, LocalJSXCommand
- Central CommandRegistry for registration and dispatch
- Permission-aware execution
"""

from __future__ import annotations
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Awaitable, TYPE_CHECKING

if TYPE_CHECKING:
    from src.agents.orchestrator import Orchestrator

logger = logging.getLogger(__name__)


class CommandType(str, Enum):
    """Claude Code's three command types."""
    PROMPT = "prompt"            # Sends structured prompt to LLM with tools injected
    LOCAL = "local"              # Runs in-process, returns plain text
    LOCAL_JSX = "local_jsx"      # Runs in-process, renders rich terminal UI


@dataclass
class CommandResult:
    """Result from executing a command."""
    success: bool
    output: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: Optional[str] = None


class Command(ABC):
    """Base command — matches Claude Code's Command interface.

    Each command specifies:
    - type: PROMPT (sends prompt to LLM), LOCAL (in-process), LOCAL_JSX (rich UI)
    - name: The command name (e.g., "commit", "review")
    - description: Help text for the command
    - aliases: Alternative names for the command
    - permission: Required permission level
    """

    def __init__(
        self,
        name: str,
        description: str,
        command_type: CommandType = CommandType.LOCAL,
        aliases: Optional[List[str]] = None,
        permission_scope: Optional[str] = None,
        hidden: bool = False,
    ):
        self.name = name
        self.description = description
        self.command_type = command_type
        self.aliases = aliases or []
        self.permission_scope = permission_scope
        self.hidden = hidden

    @abstractmethod
    async def execute(
        self,
        args: str,
        orchestrator: Optional["Orchestrator"] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> CommandResult:
        """Execute the command."""
        ...

    def get_prompt_for_command(self) -> Optional[str]:
        """Get the LLM-readable prompt for PromptCommand types.

        Matches Claude Code's getPromptForCommand() pattern.
        Only relevant for PROMPT type commands.
        """
        return None

    def get_short_help(self) -> str:
        """Get short help text for listing."""
        return f"/{self.name}  {self.description}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "type": self.command_type.value,
            "aliases": self.aliases,
            "hidden": self.hidden,
        }


class PromptCommand(Command):
    """A command that sends a structured prompt to an agent.

    Matches Claude Code's PromptCommand type where commands inject
    specialized prompts and tools into the LLM call.
    """

    def __init__(
        self,
        name: str,
        description: str,
        prompt_template: str,
        agent_name: Optional[str] = None,
        inject_tools: Optional[List[str]] = None,
        aliases: Optional[List[str]] = None,
        permission_scope: Optional[str] = None,
    ):
        super().__init__(
            name=name,
            description=description,
            command_type=CommandType.PROMPT,
            aliases=aliases,
            permission_scope=permission_scope,
        )
        self.prompt_template = prompt_template
        self.agent_name = agent_name
        self.inject_tools = inject_tools or []

    async def execute(
        self,
        args: str,
        orchestrator: Optional["Orchestrator"] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> CommandResult:
        start = time.time()

        if not orchestrator:
            return CommandResult(
                success=False,
                output="Orchestrator not available",
                error="No orchestrator provided",
            )

        # Build the prompt from template and args
        prompt = self.prompt_template.replace("{{args}}", args)
        if context:
            ctx_str = "\n".join(f"{k}: {v}" for k, v in context.items())
            prompt = prompt.replace("{{context}}", ctx_str)

        # Route to the specified agent or let orchestrator decide
        if self.agent_name:
            agent = orchestrator.get_agent(self.agent_name)
            if agent:
                result = await agent.run(prompt, context)
            else:
                result = await orchestrator.process(prompt, context)
        else:
            result = await orchestrator.process(prompt, context)

        duration = (time.time() - start) * 1000

        findings = result.get("findings", [])
        output_lines = [
            f"Task: {result.get('task_id', 'N/A')}",
            f"Status: {result.get('status', 'unknown').upper()}",
        ]
        if findings:
            output_lines.append(f"Findings: {len(findings)}")
            for f in findings[:5]:
                output_lines.append(f"  [{f.get('severity', 'INFO')}] {f.get('title', '')}")
        else:
            output_lines.append("No findings.")

        return CommandResult(
            success=result.get("status") != "error",
            output="\n".join(output_lines),
            data=result,
            duration_ms=duration,
        )

    def get_prompt_for_command(self) -> str:
        return self.prompt_template


class LocalCommand(Command):
    """A command that runs entirely in-process.

    Matches Claude Code's LocalCommand type for operations that
    don't need LLM inference (e.g., /cost, /version, /help).
    """

    def __init__(
        self,
        name: str,
        description: str,
        handler: Callable[[str, Optional["Orchestrator"], Optional[Dict]], Awaitable[CommandResult]],
        aliases: Optional[List[str]] = None,
        permission_scope: Optional[str] = None,
        hidden: bool = False,
    ):
        super().__init__(
            name=name,
            description=description,
            command_type=CommandType.LOCAL,
            aliases=aliases,
            permission_scope=permission_scope,
            hidden=hidden,
        )
        self._handler = handler

    async def execute(
        self,
        args: str,
        orchestrator: Optional["Orchestrator"] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> CommandResult:
        return await self._handler(args, orchestrator, context)


class LocalJSXCommand(Command):
    """A command that runs in-process and renders rich terminal UI.

    Matches Claude Code's LocalJSXCommand type (React/Ink based).
    Falls back to plain text if rich terminal is unavailable.
    """

    def __init__(
        self,
        name: str,
        description: str,
        handler: Callable[[str, Optional["Orchestrator"], Optional[Dict]], Awaitable[CommandResult]],
        render_jsx: Optional[Callable[[CommandResult], str]] = None,
        aliases: Optional[List[str]] = None,
        permission_scope: Optional[str] = None,
    ):
        super().__init__(
            name=name,
            description=description,
            command_type=CommandType.LOCAL_JSX,
            aliases=aliases,
            permission_scope=permission_scope,
        )
        self._handler = handler
        self._render_jsx = render_jsx

    async def execute(
        self,
        args: str,
        orchestrator: Optional["Orchestrator"] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> CommandResult:
        return await self._handler(args, orchestrator, context)

    def render(self, result: CommandResult) -> str:
        """Render rich output for this command."""
        if self._render_jsx:
            return self._render_jsx(result)
        return result.output


class CommandRegistry:
    """Central registry for slash commands.

    Matches Claude Code's src/commands.ts registration system.
    Commands are registered by name and looked up by name or alias.
    """

    def __init__(self):
        self._commands: Dict[str, Command] = {}

    def register(self, command: Command) -> None:
        """Register a command."""
        self._commands[command.name] = command
        logger.info(f"Registered command: /{command.name} ({command.command_type.value})")

    def register_all(self, commands: List[Command]) -> None:
        """Register multiple commands."""
        for cmd in commands:
            self.register(cmd)

    def get(self, name: str) -> Optional[Command]:
        """Get a command by name or alias."""
        # Direct lookup
        if name in self._commands:
            return self._commands[name]

        # Alias lookup
        for cmd in self._commands.values():
            if name in cmd.aliases:
                return cmd

        return None

    def __len__(self) -> int:
        """Return the number of registered commands."""
        return len(self._commands)

    def get_all(self, include_hidden: bool = False) -> List[Command]:
        """Get all registered commands."""
        if include_hidden:
            return list(self._commands.values())
        return [c for c in self._commands.values() if not c.hidden]

    def get_by_type(self, command_type: CommandType) -> List[Command]:
        """Get all commands of a specific type."""
        return [c for c in self._commands.values() if c.command_type == command_type]

    def parse(self, input_line: str) -> Optional[tuple[Command, str]]:
        """Parse an input line and extract command + args.

        Args:
            input_line: e.g., "/commit --message 'fix bug'"

        Returns:
            Tuple of (Command, args_string) or None if not a command
        """
        input_line = input_line.strip()
        if not input_line.startswith("/"):
            return None

        # Extract command name and args
        parts = input_line[1:].split(" ", 1)
        cmd_name = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        cmd = self.get(cmd_name)
        if cmd:
            return cmd, args
        return None

    async def execute(
        self,
        input_line: str,
        orchestrator: Optional["Orchestrator"] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[CommandResult]:
        """Parse and execute a command from an input line.

        Args:
            input_line: e.g., "/review check this code"
            orchestrator: The orchestrator instance
            context: Optional context

        Returns:
            CommandResult or None if not a valid command
        """
        parsed = self.parse(input_line)
        if not parsed:
            return None

        cmd, args = parsed
        return await cmd.execute(args, orchestrator, context)

    def get_help_text(self) -> str:
        """Get formatted help text for all commands."""
        lines = ["Available commands:", ""]

        prompt_cmds = self.get_by_type(CommandType.PROMPT)
        local_cmds = self.get_by_type(CommandType.LOCAL)
        jsx_cmds = self.get_by_type(CommandType.LOCAL_JSX)

        if prompt_cmds:
            lines.append("  AI-Powered Commands:")
            for c in prompt_cmds:
                if not c.hidden:
                    aliases = f" (aliases: {', '.join(c.aliases)})" if c.aliases else ""
                    lines.append(f"    /{c.name:<12} {c.description}{aliases}")

        if local_cmds:
            lines.append("  Utility Commands:")
            for c in local_cmds:
                if not c.hidden:
                    aliases = f" (aliases: {', '.join(c.aliases)})" if c.aliases else ""
                    lines.append(f"    /{c.name:<12} {c.description}{aliases}")

        if jsx_cmds:
            lines.append("  Rich Terminal Commands:")
            for c in jsx_cmds:
                if not c.hidden:
                    lines.append(f"    /{c.name:<12} {c.description}")

        return "\n".join(lines)
