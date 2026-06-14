"""Hook System — Git hooks with permission verification.

Ported from Claude Code's hook system architecture.
"""

from src.hooks.git_hooks import (
    HookRegistry,
    HookContext,
    HookResult,
    BaseHook,
    PreCommitHook,
    PrePushHook,
    CommitMsgHook,
    execute_hook,
    HOOK_TYPES,
)

__all__ = [
    "HookRegistry",
    "HookContext",
    "HookResult",
    "BaseHook",
    "PreCommitHook",
    "PrePushHook",
    "CommitMsgHook",
    "execute_hook",
    "HOOK_TYPES",
]
