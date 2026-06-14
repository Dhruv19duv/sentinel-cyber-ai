"""Permission System — Fine-grained tool-level access control.

Ported from Anthropic Claude Code's permission system (src/hooks/toolPermission/).
Provides rule-based access control for tools, files, and operations.
"""

from src.permissions.permission_manager import (
    PermissionManager,
    PermissionMode,
    PermissionRule,
    PermissionResult,
    DEFAULT_RULES,
)

__all__ = [
    "PermissionManager",
    "PermissionMode",
    "PermissionRule",
    "PermissionResult",
    "DEFAULT_RULES",
]
