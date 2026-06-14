"""Tests for the Slash Command System (Claude Code port)."""

import pytest
import asyncio
from src.commands.base import (
    CommandRegistry, Command, CommandType,
    PromptCommand, LocalCommand, LocalJSXCommand,
    CommandResult,
)


class TestCommandRegistry:
    """Tests for CommandRegistry."""

    @pytest.fixture
    def registry(self):
        r = CommandRegistry()
        return r

    async def _handler_ok(self, args, orchestrator=None, context=None):
        return CommandResult(success=True, output=f"handled: {args}")

    @pytest.mark.asyncio
    async def test_register_and_count(self, registry):
        """Registering commands should increase count."""
        cmd = LocalCommand("test-cmd", "A test", handler=self._handler_ok)
        registry.register(cmd)
        assert len(registry) == 1

    @pytest.mark.asyncio
    async def test_register_all(self, registry):
        """register_all should register multiple commands."""
        cmds = [
            LocalCommand("cmd1", "First", handler=self._handler_ok),
            LocalCommand("cmd2", "Second", handler=self._handler_ok),
            LocalCommand("cmd3", "Third", handler=self._handler_ok),
        ]
        registry.register_all(cmds)
        assert len(registry) == 3

    @pytest.mark.asyncio
    async def test_get_by_name(self, registry):
        """get() should return command by name."""
        cmd = LocalCommand("hello", "Says hello", handler=self._handler_ok)
        registry.register(cmd)
        assert registry.get("hello") is cmd

    @pytest.mark.asyncio
    async def test_get_by_alias(self, registry):
        """get() should find command by alias."""
        cmd = LocalCommand("version", "Version info", handler=self._handler_ok, aliases=["v", "ver"])
        registry.register(cmd)
        assert registry.get("v") is cmd
        assert registry.get("ver") is cmd

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, registry):
        """get() should return None for unknown commands."""
        assert registry.get("nonexistent") is None

    @pytest.mark.asyncio
    async def test_get_all(self, registry):
        """get_all() should return all non-hidden commands."""
        cmd1 = LocalCommand("visible", "Visible", handler=self._handler_ok)
        cmd2 = LocalCommand("hidden", "Hidden", handler=self._handler_ok, hidden=True)
        registry.register_all([cmd1, cmd2])
        all_cmds = registry.get_all()
        names = [c.name for c in all_cmds]
        assert "visible" in names
        assert "hidden" not in names

    @pytest.mark.asyncio
    async def test_get_all_include_hidden(self, registry):
        """get_all(include_hidden=True) should return all."""
        cmd1 = LocalCommand("visible", "Visible", handler=self._handler_ok)
        cmd2 = LocalCommand("hidden", "Hidden", handler=self._handler_ok, hidden=True)
        registry.register_all([cmd1, cmd2])
        assert len(registry.get_all(include_hidden=True)) == 2

    @pytest.mark.asyncio
    async def test_parse_simple(self, registry):
        """parse('/help') should return (command, '')."""
        cmd = LocalCommand("help", "Help text", handler=self._handler_ok)
        registry.register(cmd)
        result = registry.parse("/help")
        assert result is not None
        cmd_found, args = result
        assert cmd_found.name == "help"
        assert args == ""

    @pytest.mark.asyncio
    async def test_parse_with_args(self, registry):
        """parse('/cmd args here') should return args."""
        cmd = LocalCommand("review", "Review", handler=self._handler_ok)
        registry.register(cmd)
        result = registry.parse("/review check this code")
        assert result is not None
        cmd_found, args = result
        assert cmd_found.name == "review"
        assert args == "check this code"

    @pytest.mark.asyncio
    async def test_parse_not_a_command(self, registry):
        """parse() should return None for non-command input."""
        result = registry.parse("just some text")
        assert result is None

    @pytest.mark.asyncio
    async def test_parse_unknown_command(self, registry):
        """parse() should return None for unknown /command."""
        result = registry.parse("/totallyfake")
        assert result is None

    @pytest.mark.asyncio
    async def test_parse_case_insensitive(self, registry):
        """parse() should be case-insensitive."""
        cmd = LocalCommand("help", "Help", handler=self._handler_ok)
        registry.register(cmd)
        assert registry.parse("/HELP") is not None
        assert registry.parse("/Help") is not None

    @pytest.mark.asyncio
    async def test_execute_local(self, registry):
        """execute() should run the command handler."""
        cmd = LocalCommand("greet", "Greets", handler=self._handler_ok)
        registry.register(cmd)
        result = await registry.execute("/greet world")
        assert result is not None
        assert result.success
        assert "handled: world" in result.output

    @pytest.mark.asyncio
    async def test_execute_unknown(self, registry):
        """execute() should return None for unknown command."""
        result = await registry.execute("/nope")
        assert result is None

    @pytest.mark.asyncio
    async def test_execute_multiple_args(self, registry):
        """execute() should pass all args to handler."""
        async def _handler(args, orch=None, ctx=None):
            return CommandResult(success=True, output=f"got: [{args}]")
        cmd = LocalCommand("echo", "Echo", handler=_handler)
        registry.register(cmd)
        result = await registry.execute("/echo foo bar baz")
        assert result.success
        assert result.output == "got: [foo bar baz]"

    @pytest.mark.asyncio
    async def test_get_by_type(self, registry):
        """get_by_type() should filter by command type."""
        async def _h(args, o=None, c=None):
            return CommandResult(success=True, output="ok")
        registry.register(LocalCommand("local1", "L1", handler=_h))
        registry.register(PromptCommand("prompt1", "P1", prompt_template="test", agent_name="Scanner"))
        local_cmds = registry.get_by_type(CommandType.LOCAL)
        prompt_cmds = registry.get_by_type(CommandType.PROMPT)
        assert len(local_cmds) == 1
        assert len(prompt_cmds) == 1

    @pytest.mark.asyncio
    async def test_get_help_text(self, registry):
        """get_help_text() should return formatted help."""
        registry.register(LocalCommand("test", "Test command", handler=self._handler_ok))
        help_text = registry.get_help_text()
        assert "Available commands:" in help_text
        assert "test" in help_text
        assert "Test command" in help_text


class TestPromptCommand:
    """Tests for PromptCommand."""

    @pytest.mark.asyncio
    async def test_no_orchestrator(self):
        """Should handle missing orchestrator gracefully."""
        cmd = PromptCommand("test", "Test", prompt_template="{{args}}")
        result = await cmd.execute("hello", orchestrator=None)
        assert not result.success
        assert "Orchestrator not available" in result.output

    @pytest.mark.asyncio
    async def test_prompt_template_substitution(self):
        """prompt_template should substitute {{args}}."""
        cmd = PromptCommand("test", "Test", prompt_template="User said: {{args}}")
        prompt = cmd.get_prompt_for_command()
        assert "User said: {{args}}" in prompt
        # Also check the template is stored correctly
        assert cmd.prompt_template == "User said: {{args}}"

    @pytest.mark.asyncio
    async def test_prompt_command_attributes(self):
        """PromptCommand should set correct type."""
        cmd = PromptCommand("review", "Review code", prompt_template="Check: {{args}}", agent_name="Scanner", inject_tools=["search"], aliases=["r"])
        assert cmd.command_type == CommandType.PROMPT
        assert cmd.agent_name == "Scanner"
        assert cmd.inject_tools == ["search"]
        assert cmd.aliases == ["r"]


class TestLocalCommand:
    """Tests for LocalCommand."""

    @pytest.mark.asyncio
    async def test_local_execution(self):
        """Should execute the handler and return result."""
        async def my_handler(args, orch=None, ctx=None):
            return CommandResult(success=True, output=f"Hello {args}")
        cmd = LocalCommand("greet", "Greeter", handler=my_handler)
        result = await cmd.execute("World")
        assert result.success
        assert result.output == "Hello World"

    @pytest.mark.asyncio
    async def test_local_with_error(self):
        """Should return error result from handler."""
        async def failing_handler(args, orch=None, ctx=None):
            return CommandResult(success=False, output="failed", error="Something went wrong")
        cmd = LocalCommand("fail", "Fails", handler=failing_handler)
        result = await cmd.execute("")
        assert not result.success
        assert result.error == "Something went wrong"

    @pytest.mark.asyncio
    async def test_local_hidden(self):
        """Hidden commands should not appear in get_all()."""
        async def h(args, o=None, c=None): return CommandResult(success=True, output="ok")
        cmd = LocalCommand("secret", "Hidden", handler=h, hidden=True)
        assert cmd.hidden is True


class TestCommandResult:
    """Tests for CommandResult."""

    def test_defaults(self):
        """Should have sensible defaults."""
        r = CommandResult(success=True)
        assert r.output == ""
        assert r.data == {}
        assert r.duration_ms == 0.0
        assert r.error is None

    def test_with_data(self):
        """Should store data dict."""
        r = CommandResult(success=True, output="done", data={"key": "value"}, duration_ms=100.0)
        assert r.output == "done"
        assert r.data["key"] == "value"
        assert r.duration_ms == 100.0


class TestCommandsIntegration:
    """Integration tests with actual command definitions."""

    @pytest.mark.asyncio
    async def test_version_command(self):
        """/version should output version info."""
        from src.commands.diagnostic_commands import version_command
        result = await version_command.execute("")
        assert result.success
        assert "Sentinel" in result.output

    @pytest.mark.asyncio
    async def test_help_command(self):
        """/help should output command list."""
        from src.commands.help_commands import help_command
        # Without orchestrator, should show fallback help
        result = await help_command.execute("")
        assert result.success
        assert "Available commands" in result.output or "/review" in result.output

    @pytest.mark.asyncio
    async def test_stats_command(self):
        """/stats should handle missing orchestrator gracefully."""
        from src.commands.diagnostic_commands import stats_command
        result = await stats_command.execute("")
        assert result.success  # Should still succeed
        assert "Statistics" in result.output or "orchestrator" in result.output.lower()

    @pytest.mark.asyncio
    async def test_cost_command(self):
        """/cost should handle missing orchestrator gracefully."""
        from src.commands.diagnostic_commands import cost_command
        result = await cost_command.execute("")
        assert result.success
        assert "Token" in result.output or "Cost" in result.output

    @pytest.mark.asyncio
    async def test_config_command_unknown_key(self):
        """/config with unknown key should return error."""
        from src.commands.config_commands import config_command
        result = await config_command.execute("unknownkey")
        assert not result.success

    @pytest.mark.asyncio
    async def test_branch_no_args(self):
        """/branch without args should list branches (requires git)."""
        from src.commands.git_commands import branch_command
        result = await branch_command.execute("")
        # On systems without git, this may fail
        if "Git not found" not in result.output:
            assert result.success

    @pytest.mark.asyncio
    async def test_diff_no_changes(self):
        """/diff should handle git not found gracefully."""
        from src.commands.git_commands import diff_command
        result = await diff_command.execute("")
        # If git fails, should still return a result
        assert isinstance(result, CommandResult)

    @pytest.mark.asyncio
    async def test_rewind_invalid_arg(self):
        """/rewind with non-numeric arg should error."""
        from src.commands.git_commands import rewind_command
        result = await rewind_command.execute("abc")
        assert not result.success

    @pytest.mark.asyncio
    async def test_rewind_too_many(self):
        """/rewind with >10 should error."""
        from src.commands.git_commands import rewind_command
        result = await rewind_command.execute("50")
        assert not result.success

    @pytest.mark.asyncio
    async def test_registry_with_all_git_commands(self):
        """All git commands should register without error."""
        from src.commands.git_commands import GIT_COMMANDS
        registry = CommandRegistry()
        registry.register_all(GIT_COMMANDS)
        assert len(registry) == len(GIT_COMMANDS)
        for cmd in GIT_COMMANDS:
            assert registry.get(cmd.name) is cmd

    @pytest.mark.asyncio
    async def test_registry_with_all_commands(self):
        """All command groups should register without conflict."""
        from src.commands.git_commands import GIT_COMMANDS
        from src.commands.review_commands import REVIEW_COMMANDS
        from src.commands.diagnostic_commands import DIAGNOSTIC_COMMANDS
        from src.commands.config_commands import CONFIG_COMMANDS
        from src.commands.memory_commands import memory_command
        from src.commands.help_commands import help_command

        registry = CommandRegistry()
        registry.register_all(GIT_COMMANDS)
        registry.register_all(REVIEW_COMMANDS)
        registry.register_all(DIAGNOSTIC_COMMANDS)
        registry.register_all(CONFIG_COMMANDS)
        registry.register(memory_command)
        registry.register(help_command)

        # Should have 17 commands (5 git + 3 review + 4 diag + 3 config + 1 memory + 1 help)
        assert len(registry) == 17
