"""Hook System — Git hooks with permission verification.

Ported from Claude Code's hook system (src/hooks/).
Claude Code uses permission hooks to verify tool operations before execution,
and git hooks (pre-commit, pre-push) for workflow automation.

Key concepts:
- Permission Hooks: Verify tool operations before they execute
- Git Hooks: Automate git workflows (pre-commit, pre-push)
- Hook Chain: Multiple verifiers run in sequence
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import subprocess
import sys
import textwrap
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from src.commands.base import CommandRegistry
from src.permissions.permission_manager import PermissionManager, PermissionResult

logger = logging.getLogger(__name__)

# Known hook types
HOOK_TYPES = [
    "pre-commit",
    "pre-push",
    "commit-msg",
    "prepare-commit-msg",
    "post-commit",
    "post-checkout",
    "post-merge",
    "pre-rebase",
]


@dataclass
class HookContext:
    """Context for a hook execution."""
    hook_type: str
    args: List[str] = field(default_factory=list)
    repo_path: str = "."
    env: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hook_type": self.hook_type,
            "args": self.args,
            "repo_path": self.repo_path,
            "metadata": self.metadata,
        }


@dataclass
class HookResult:
    """Result from a hook execution."""
    success: bool
    output: str = ""
    errors: List[str] = field(default_factory=list)
    duration_ms: float = 0.0


class BaseHook(ABC):
    """Base class for hooks."""

    def __init__(self, name: str, hook_type: str):
        self.name = name
        self.hook_type = hook_type

    @abstractmethod
    async def run(self, context: HookContext) -> HookResult:
        ...


def _run_git(args: str) -> tuple:
    """Run a git command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(f"git {args}", shell=True, capture_output=True, text=True, timeout=15)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


class PreCommitHook(BaseHook):
    """Pre-commit hook — runs checks before each commit.

    Claude Code's pre-commit verifies:
    - Permission rules for staged changes
    - Secret scanning on staged files
    - Code quality checks
    """

    def __init__(self, permission_manager: Optional[PermissionManager] = None):
        super().__init__("sentinel-pre-commit", "pre-commit")
        self.permission_manager = permission_manager

    async def run(self, context: HookContext) -> HookResult:
        import time
        start = time.time()
        errors = []

        # Check: verify staged file permissions
        ok, out, err = _run_git("diff --cached --name-only")
        if ok and out.strip():
            files = out.strip().split("\n")
            for f in files:
                if not f.strip():
                    continue
                if self.permission_manager:
                    result = self.permission_manager.check_file_operation("write", f)
                    if not result.allowed and not result.requires_confirmation:
                        errors.append(f"File write denied: {f} ({result.reason})")

        # Check: look for secrets in staged changes
        ok, diff_out, _ = _run_git("diff --cached")
        if diff_out:
            secret_patterns = [
                "-----BEGIN", "sk-", "AKIA", "ghp_", "gho_",
                "xoxp-", "xoxb-",
            ]
            for i, line in enumerate(diff_out.split("\n")):
                for pattern in secret_patterns:
                    if pattern in line and line.startswith("+"):
                        errors.append(f"Potential secret in staged changes: {pattern}...")
                        break

        duration = (time.time() - start) * 1000
        success = len(errors) == 0

        if success:
            return HookResult(success=True, output="Pre-commit checks passed.", duration_ms=duration)
        return HookResult(
            success=False,
            output=f"Pre-commit checks failed ({len(errors)} issues)",
            errors=errors,
            duration_ms=duration,
        )


class PrePushHook(BaseHook):
    """Pre-push hook — verifies before pushing to remote.

    Similar to Claude Code's pre-push verification.
    """

    def __init__(self, permission_manager: Optional[PermissionManager] = None):
        super().__init__("sentinel-pre-push", "pre-push")
        self.permission_manager = permission_manager

    async def run(self, context: HookContext) -> HookResult:
        import time
        start = time.time()
        errors = []

        # Verify git:push permission
        if self.permission_manager:
            result = self.permission_manager.check("git", "push")
            if not result.allowed and not result.requires_confirmation:
                errors.append(f"Push denied: {result.reason}")

        # Check for unpushed commits with potential issues
        ok, out, _ = _run_git("log origin/main..HEAD --oneline")
        if ok and out.strip():
            commits = out.strip().split("\n")
            for c in commits:
                if any(kw in c.lower() for kw in ["fixup!", "wip", "debug", "temp"]):
                    errors.append(f"Unclean commit message: {c}")

        duration = (time.time() - start) * 1000
        success = len(errors) == 0
        return HookResult(
            success=success,
            output=f"Pre-push {'passed' if success else 'failed'} ({len(errors)} issues)" if errors else "Pre-push checks passed.",
            errors=errors,
            duration_ms=duration,
        )


class CommitMsgHook(BaseHook):
    """Commit message hook — validates commit message format.

    Matches Claude Code's commit message validation.
    """

    def __init__(self):
        super().__init__("sentinel-commit-msg", "commit-msg")

    async def run(self, context: HookContext) -> HookResult:
        import time
        start = time.time()
        errors = []

        # Read commit message file
        msg_file = context.args[0] if context.args else ".git/COMMIT_EDITMSG"
        try:
            with open(msg_file, "r") as f:
                msg = f.read().strip()
        except Exception:
            msg = ""

        if not msg:
            errors.append("Commit message is empty")
        else:
            lines = msg.split("\n")
            first_line = lines[0]

            # Check conventional commit format
            conventional_patterns = ["feat:", "fix:", "chore:", "docs:", "style:", "refactor:",
                                     "perf:", "test:", "build:", "ci:", "revert:"]
            if not any(first_line.startswith(p) for p in conventional_patterns):
                errors.append(
                    f"Commit message should follow conventional commits format "
                    f"(e.g., 'feat: add login'). Got: '{first_line[:50]}'"
                )

            # Check title length
            if len(first_line) > 72:
                errors.append(f"First line is {len(first_line)} chars (max 72)")

            # Check for WIP
            if first_line.lower().startswith("wip"):
                errors.append("WIP commits should not be pushed")

        duration = (time.time() - start) * 1000
        success = len(errors) == 0
        return HookResult(
            success=success,
            output=f"Commit message {'valid' if success else 'invalid'} ({len(errors)} issues)",
            errors=errors,
            duration_ms=duration,
        )


# ── Hook Registry ──


class HookRegistry:
    """Registry of hooks that can be installed and run.

    Matches Claude Code's hook registration system.
    """

    def __init__(self, permission_manager: Optional[PermissionManager] = None):
        self._hooks: Dict[str, List[BaseHook]] = {ht: [] for ht in HOOK_TYPES}
        self.permission_manager = permission_manager

    def register(self, hook: BaseHook) -> None:
        """Register a hook."""
        if hook.hook_type in self._hooks:
            self._hooks[hook.hook_type].append(hook)
            logger.info(f"Hook registered: {hook.name} ({hook.hook_type})")

    def register_defaults(self) -> None:
        """Register default hooks."""
        self.register(PreCommitHook(self.permission_manager))
        self.register(PrePushHook(self.permission_manager))
        self.register(CommitMsgHook())

    async def run_hooks(self, hook_type: str, args: Optional[List[str]] = None) -> List[HookResult]:
        """Run all hooks of a given type."""
        hooks = self._hooks.get(hook_type, [])
        if not hooks:
            return [HookResult(success=True, output=f"No {hook_type} hooks registered.")]

        context = HookContext(hook_type=hook_type, args=args or [])
        results = await asyncio.gather(*[hook.run(context) for hook in hooks])
        return results

    def install_git_hooks(self, repo_path: str = ".") -> Dict[str, bool]:
        """Install git hook scripts in the .git/hooks directory.

        Writes shell scripts that invoke Sentinel's hook system.
        """
        git_dir = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True, text=True, timeout=5,
            cwd=repo_path,
        ).stdout.strip()

        if not git_dir:
            logger.error(f"Not a git repository: {repo_path}")
            return {}

        hooks_dir = os.path.join(repo_path, git_dir, "hooks")
        os.makedirs(hooks_dir, exist_ok=True)

        results = {}
        for hook_type in self._hooks:
            if self._hooks[hook_type]:
                script = self._generate_hook_script(hook_type)
                hook_path = os.path.join(hooks_dir, hook_type)
                try:
                    with open(hook_path, "w") as f:
                        f.write(script)
                    # Make executable
                    if sys.platform != "win32":
                        os.chmod(hook_path, os.stat(hook_path).st_mode | stat.S_IEXEC)
                    results[hook_type] = True
                    logger.info(f"Installed git hook: {hook_type}")
                except Exception as e:
                    logger.error(f"Failed to install hook {hook_type}: {e}")
                    results[hook_type] = False

        return results

    def _generate_hook_script(self, hook_type: str) -> str:
        """Generate a shell script for a git hook that calls Sentinel."""
        return textwrap.dedent(f"""\
        #!/bin/sh
        # Sentinel AI Hook — {hook_type}
        # Installed by Sentinel Cyber AI's Hook System (Claude Code feature port)
        
        SENTINEL_HOOK=1 python -m src.main hook {hook_type} "$@"
        if [ $? -ne 0 ]; then
            echo "❌ Sentinel {hook_type} hook failed"
            exit 1
        fi
        """)

    def get_status(self) -> Dict[str, Any]:
        """Get hook system status."""
        return {
            "hook_types": list(self._hooks.keys()),
            "hooks": {
                ht: [h.name for h in hooks]
                for ht, hooks in self._hooks.items()
                if hooks
            },
        }


# ── Hook Executor (for CLI) ──


async def execute_hook(hook_type: str, args: List[str], orchestrator=None) -> HookResult:
    """Execute hooks of a given type.

    Args:
        hook_type: e.g., "pre-commit", "pre-push", "commit-msg"
        args: Arguments passed to the hook
        orchestrator: Optional orchestrator for permission checking

    Returns:
        Aggregate HookResult
    """
    from src.permissions.permission_manager import PermissionManager
    pm = orchestrator.permission_manager if orchestrator else PermissionManager()

    registry = HookRegistry(permission_manager=pm)
    registry.register_defaults()

    results = await registry.run_hooks(hook_type, args)

    # Aggregate
    all_success = all(r.success for r in results)
    all_outputs = [r.output for r in results]
    all_errors = []
    for r in results:
        all_errors.extend(r.errors)

    return HookResult(
        success=all_success,
        output="\n".join(all_outputs),
        errors=all_errors,
        duration_ms=sum(r.duration_ms for r in results),
    )
