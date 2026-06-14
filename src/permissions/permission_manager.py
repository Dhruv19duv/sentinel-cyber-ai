"""
Permission Manager — Fine-grained tool-level access control.

Ported from Anthropic Claude Code's src/hooks/toolPermission/ system.

Claude Code's permission system uses rules like:
  - Bash(git *)          — Allow git commands in bash
  - FileEdit(/src/*)     — Allow file edits in /src/
  - Bash(rm *)           — Ask before rm commands
  - FileWrite(*)         — Deny all file writes (default)

Our system implements the same pattern with:
  - Scope patterns (e.g., "bash:git:*", "file:edit:/src/*")
  - Permission modes: allow, deny, ask, plan
  - Rule precedence (most specific wins)
  - Audit logging of all permission checks
"""

from __future__ import annotations
import fnmatch
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)


class PermissionMode(str, Enum):
    """Permission modes — matching Claude Code's tool permission levels."""
    ALLOW = "allow"    # Auto-approved, no user prompt
    DENY = "deny"      # Blocked, returns error
    ASK = "ask"        # Ask user for permission each time
    PLAN = "plan"      # Added to plan for batch approval


@dataclass
class PermissionRule:
    """A single permission rule with scope pattern.

    Matches Claude Code's permission hook rules.
    Scope uses glob patterns: e.g., "bash:git:*", "file:edit:/src/*"
    """
    scope: str          # e.g., "bash:git:*", "file:read:*"
    mode: PermissionMode
    description: str = ""
    priority: int = 0   # Higher priority wins when scopes overlap

    def matches(self, operation: str, resource: str = "") -> bool:
        """Check if this rule matches an operation and optional resource.

        Args:
            operation: The operation to check (e.g., "bash", "file:edit", "sandbox")
            resource: The specific resource (e.g., "git status", "/src/main.py")

        Returns:
            True if this rule applies
        """
        # Full scope match: "bash:git:*"
        scope_parts = self.scope.split(":", 1)

        if len(scope_parts) == 1:
            # Simple scope: "bash" matches any bash operation
            return fnmatch.fnmatch(operation, scope_parts[0])

        # Compound scope: "bash:git:*" matches operation="bash" with resource="git"
        op_pattern = scope_parts[0]
        res_pattern = scope_parts[1]

        if not fnmatch.fnmatch(operation, op_pattern):
            return False

        # No resource pattern means it matches
        if not res_pattern or res_pattern == "*":
            return True

        # Resource pattern exists but no resource provided → doesn't match
        if not resource:
            return False

        return fnmatch.fnmatch(resource, res_pattern)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scope": self.scope,
            "mode": self.mode.value,
            "description": self.description,
            "priority": self.priority,
        }


@dataclass
class PermissionResult:
    """Result of a permission check."""
    allowed: bool
    mode: PermissionMode
    rule: Optional[PermissionRule] = None
    reason: str = ""
    requires_confirmation: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "mode": self.mode.value,
            "rule": self.rule.scope if self.rule else None,
            "reason": self.reason,
            "requires_confirmation": self.requires_confirmation,
        }


# ── Default rules ──
# Modeled after Claude Code's default permission configuration.

DEFAULT_RULES = [
    # Allow all analysis/request operations by default
    PermissionRule(
        scope="request:*",
        mode=PermissionMode.ALLOW,
        description="Allow all analysis and query requests by default",
        priority=1,
    ),
    PermissionRule(
        scope="bash:git*",
        mode=PermissionMode.ALLOW,
        description="Allow all git commands (status, log, diff, add, commit, push)",
        priority=10,
    ),
    PermissionRule(
        scope="bash:npm:*",
        mode=PermissionMode.ASK,
        description="Ask before npm/pnpm/yarn installs",
        priority=5,
    ),
    PermissionRule(
        scope="bash:rm:*",
        mode=PermissionMode.ASK,
        description="Ask before rm -rf or destructive file operations",
        priority=5,
    ),
    PermissionRule(
        scope="bash:docker:*",
        mode=PermissionMode.ASK,
        description="Ask before docker commands",
        priority=5,
    ),
    PermissionRule(
        scope="bash:curl:*",
        mode=PermissionMode.ALLOW,
        description="Allow curl/wget requests",
        priority=5,
    ),
    PermissionRule(
        scope="bash:cat:*",
        mode=PermissionMode.ALLOW,
        description="Allow cat and read-only commands",
        priority=5,
    ),
    PermissionRule(
        scope="bash:chmod:*",
        mode=PermissionMode.ASK,
        description="Ask before chmod/chown",
        priority=5,
    ),
    PermissionRule(
        scope="file:read:*",
        mode=PermissionMode.ALLOW,
        description="Allow reading any file",
        priority=1,
    ),
    PermissionRule(
        scope="file:write:*",
        mode=PermissionMode.ASK,
        description="Ask before writing to any file",
        priority=1,
    ),
    PermissionRule(
        scope="file:delete:*",
        mode=PermissionMode.DENY,
        description="Deny file deletion by default",
        priority=1,
    ),
    PermissionRule(
        scope="sandbox:*",
        mode=PermissionMode.ASK,
        description="Ask before sandbox code execution",
        priority=1,
    ),
    PermissionRule(
        scope="network:*",
        mode=PermissionMode.ASK,
        description="Ask before network requests",
        priority=1,
    ),
    PermissionRule(
        scope="git:commit",
        mode=PermissionMode.ASK,
        description="Ask before committing changes",
        priority=10,
    ),
    PermissionRule(
        scope="git:push",
        mode=PermissionMode.ASK,
        description="Ask before pushing to remote",
        priority=10,
    ),
    PermissionRule(
        scope="git:rewind",
        mode=PermissionMode.ASK,
        description="Ask before rewinding commits",
        priority=10,
    ),
]


class PermissionManager:
    """Manages tool-level permissions.

    Matches Claude Code's permission hook system:
    - Rules are checked by scope pattern matching (glob)
    - Most specific rule wins (highest priority)
    - Default deny for unmapped operations
    - Audit trail of all permission checks
    """

    def __init__(self, rules: Optional[List[PermissionRule]] = None):
        self._rules: List[PermissionRule] = rules or list(DEFAULT_RULES)
        self._audit_log: List[Dict[str, Any]] = []

    def check(
        self,
        operation: str,
        resource: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> PermissionResult:
        """Check if an operation is permitted.

        Args:
            operation: The operation (e.g., "bash", "file:write", "sandbox")
            resource: The specific resource (e.g., "git status", "/etc/passwd")

        Returns:
            PermissionResult with the decision
        """
        # Find matching rules, sorted by priority
        matching = [
            rule for rule in self._rules
            if rule.matches(operation, resource)
        ]
        matching.sort(key=lambda r: r.priority, reverse=True)

        if matching:
            best_rule = matching[0]
            self._log_check(operation, resource, best_rule)

            if best_rule.mode == PermissionMode.ALLOW:
                return PermissionResult(
                    allowed=True,
                    mode=PermissionMode.ALLOW,
                    rule=best_rule,
                    reason=f"Allowed by rule: {best_rule.scope}",
                )
            elif best_rule.mode == PermissionMode.DENY:
                return PermissionResult(
                    allowed=False,
                    mode=PermissionMode.DENY,
                    rule=best_rule,
                    reason=f"Denied by rule: {best_rule.scope} — {best_rule.description}",
                )
            elif best_rule.mode == PermissionMode.ASK:
                return PermissionResult(
                    allowed=True,
                    mode=PermissionMode.ASK,
                    rule=best_rule,
                    reason=f"Requires confirmation: {best_rule.scope}",
                    requires_confirmation=True,
                )
            elif best_rule.mode == PermissionMode.PLAN:
                return PermissionResult(
                    allowed=True,
                    mode=PermissionMode.PLAN,
                    rule=best_rule,
                    reason=f"Added to plan: {best_rule.scope}",
                    requires_confirmation=True,
                )

        # Default: deny with reason
        self._log_check(operation, resource, None)
        return PermissionResult(
            allowed=False,
            mode=PermissionMode.DENY,
            reason=f"No permission rule for {operation}:{resource}. Default deny.",
        )

    def check_bash(self, command: str) -> PermissionResult:
        """Check a bash command with automatic resource extraction.

        Extracts the base command (e.g., "git", "rm", "docker")
        and checks against bash:* rules.
        """
        cmd = command.strip().split()[0] if command.strip() else ""
        return self.check("bash", cmd)

    def check_file_operation(self, op: str, path: str) -> PermissionResult:
        """Check a file operation.

        Formats the operation and resource to match DEFAULT_RULES patterns.
        DEFAULT_RULES use format "file:read:*", "file:write:*", "file:delete:*"
        which means op="file" with resource="read:<path>", "write:<path>".
        """
        return self.check("file", f"{op}:{path}")

    def set_rule(
        self,
        scope: str,
        mode: str,
        description: str = "",
    ) -> PermissionRule:
        """Add or update a permission rule.

        Args:
            scope: The scope pattern (e.g., "bash:git:*")
            mode: "allow", "deny", "ask", or "plan"
            description: Human-readable description

        Returns:
            The created/updated rule
        """
        perm_mode = PermissionMode(mode.lower())

        # Remove existing rule for same scope
        self._rules = [r for r in self._rules if r.scope != scope]

        rule = PermissionRule(
            scope=scope,
            mode=perm_mode,
            description=description or f"{perm_mode.value} for {scope}",
            priority=10,
        )
        self._rules.append(rule)
        logger.info(f"Permission rule set: {scope} = {perm_mode.value}")
        return rule

    def remove_rule(self, scope: str) -> bool:
        """Remove a permission rule by scope."""
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.scope != scope]
        return len(self._rules) < before

    def list_rules(self) -> List[Dict[str, Any]]:
        """List all permission rules."""
        sorted_rules = sorted(self._rules, key=lambda r: (-r.priority, r.scope))
        return [r.to_dict() for r in sorted_rules]

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent permission check audit log."""
        return self._audit_log[-limit:]

    def _log_check(self, operation: str, resource: str, rule: Optional[PermissionRule]):
        """Log a permission check to the audit trail."""
        self._audit_log.append({
            "timestamp": time.time(),
            "operation": operation,
            "resource": resource,
            "rule": rule.scope if rule else None,
            "mode": rule.mode.value if rule else "deny(default)",
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rules": len(self._rules),
            "rules": [r.to_dict() for r in self._rules],
            "audit_log_count": len(self._audit_log),
        }
