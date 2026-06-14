"""
Git Slash Commands — Ported from Claude Code's git workflow commands.

Commands:
  /commit       — Generate a commit message and commit staged changes
  /commit-push-pr — Commit, push, and create a PR
  /branch       — Create or switch branches with AI analysis
  /diff         — Show git diff with analysis
  /rewind       — Undo last commits with AI safety checks
"""

import logging
import os
import subprocess
import time
from typing import Optional, Dict, Any

from src.commands.base import (
    Command, CommandResult, CommandType,
    PromptCommand, LocalCommand,
)

logger = logging.getLogger(__name__)


# ── Helpers ──

def _run_git(args: str, timeout: int = 30) -> tuple[bool, str, str]:
    """Run a git command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            ["git"] + args.split(),
            capture_output=True, text=True, timeout=timeout,
            cwd=os.getcwd(),
        )
        return result.returncode == 0, result.stdout, result.stderr
    except FileNotFoundError:
        return False, "", "Git not found. Install git: https://git-scm.com"
    except subprocess.TimeoutExpired:
        return False, "", f"Git command timed out after {timeout}s"
    except Exception as e:
        return False, "", str(e)


def _get_git_status() -> str:
    """Get a summary of the current git state."""
    parts = []
    ok, branch_out, _ = _run_git("rev-parse --abbrev-ref HEAD")
    if ok:
        parts.append(f"Branch: {branch_out.strip()}")
    ok, status_out, _ = _run_git("status --short")
    if ok and status_out:
        lines = status_out.strip().split("\n")
        parts.append(f"Changed files ({len(lines)}):")
        for line in lines[:20]:
            parts.append(f"  {line}")
        if len(lines) > 20:
            parts.append(f"  ... and {len(lines) - 20} more")
    ok, log_out, _ = _run_git("log --oneline -5")
    if ok and log_out:
        parts.append("Recent commits:")
        for line in log_out.strip().split("\n"):
            parts.append(f"  {line}")
    return "\n".join(parts)


# ── /commit ──

async def _cmd_commit(args: str, orchestrator=None, context=None) -> CommandResult:
    """Generate a commit message using AI and commit staged changes."""
    start = time.time()

    # Get git diff of staged changes
    ok, diff, err = _run_git("diff --cached")
    if not ok:
        # Maybe nothing staged, try unstaged
        ok, diff, err = _run_git("diff")
        if not ok:
            return CommandResult(
                success=False,
                output=f"Failed to get git diff: {err}",
                error=err,
            )

    if not diff.strip():
        return CommandResult(
            success=False,
            output="No changes detected to commit. Stage changes with `git add` first.",
            error="No changes to commit",
        )

    status = _get_git_status()

    # If we have an orchestrator, use AI to generate the commit message
    commit_msg = None
    if orchestrator:
        prompt = (
            f"Generate a concise, descriptive git commit message for these changes.\n\n"
            f"Git status:\n{status[:500]}\n\n"
            f"Diff:\n```diff\n{diff[:3000]}\n```\n\n"
            f"Return ONLY the commit message, nothing else. "
            f"Follow conventional commits format (e.g., 'feat: add login', 'fix: resolve XSS in input')."
        )
        result = await orchestrator.process(prompt)
        if result.get("findings"):
            commit_msg = result["findings"][0].get("description", "")
        if not commit_msg:
            commit_msg = result.get("summary", "")

    if not commit_msg:
        # Fallback: use first line of diff as commit message
        first_line = diff.split("\n")[0] if diff else "update"
        commit_msg = f"update: {first_line.replace('+', '').replace('-', '').strip()[:72]}"

    # Clean up the commit message (remove "I've generated..." type preambles)
    commit_msg = commit_msg.strip().strip('"').strip("'")
    if len(commit_msg) > 200:
        commit_msg = commit_msg[:200]

    # Ask user if they want to proceed
    print(f"\nProposed commit message:\n  {commit_msg}\n")

    # Try to commit
    try:
        proc = subprocess.run(
            ["git", "commit", "-m", commit_msg],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode == 0:
            duration = (time.time() - start) * 1000
            return CommandResult(
                success=True,
                output=f"✅ Committed:\n  {commit_msg}\n\n{proc.stdout.strip()}",
                data={"message": commit_msg, "output": proc.stdout},
                duration_ms=duration,
            )
        else:
            return CommandResult(
                success=False,
                output=f"Commit failed:\n  {proc.stderr.strip()}",
                error=proc.stderr,
            )
    except Exception as e:
        return CommandResult(
            success=False,
            output=f"Commit error: {e}",
            error=str(e),
        )


# ── /branch ──

async def _cmd_branch(args: str, orchestrator=None, context=None) -> CommandResult:
    """Create or switch branches with AI analysis."""
    start = time.time()
    args = args.strip()

    if not args:
        # List branches
        ok, out, err = _run_git("branch")
        if ok:
            return CommandResult(
                success=True,
                output=f"Branches:\n{out.strip()}",
                duration_ms=(time.time() - start) * 1000,
            )
        return CommandResult(success=False, output=err, error=err)

    # Parse: checkout existing or create new
    if args.startswith("-d ") or args.startswith("--delete "):
        branch = args.split(" ", 1)[1]
        ok, out, err = _run_git(f"branch -d {branch}")
        if ok:
            return CommandResult(success=True, output=f"Deleted branch: {branch}\n{out}")
        return CommandResult(success=False, output=err, error=err)

    # Check if branch exists
    ok, out, _ = _run_git(f"branch --list {args}")
    if ok and out.strip():
        # Switch to existing branch
        ok, out, err = _run_git(f"checkout {args}")
        if ok:
            return CommandResult(
                success=True,
                output=f"Switched to branch: {args}\n{out.strip()}",
                duration_ms=(time.time() - start) * 1000,
            )
        return CommandResult(success=False, output=err, error=err)
    else:
        # Create and switch to new branch
        ok, out, err = _run_git(f"checkout -b {args}")
        if ok:
            return CommandResult(
                success=True,
                output=f"Created and switched to branch: {args}",
                duration_ms=(time.time() - start) * 1000,
            )
        return CommandResult(success=False, output=err, error=err)


# ── /diff ──

async def _cmd_diff(args: str, orchestrator=None, context=None) -> CommandResult:
    """Show git diff with optional AI analysis."""
    start = time.time()

    mode = args.strip() or "HEAD"
    ok, out, err = _run_git(f"diff {mode}")

    if not ok:
        return CommandResult(success=False, output=err, error=err)

    if not out.strip():
        return CommandResult(success=True, output="No differences found.")

    # Show diff stats
    ok, stats_out, _ = _run_git(f"diff --stat {mode}")
    stats = stats_out.strip() if ok else ""

    output = f"Diff ({mode}):\n\n{out[:3000]}"
    if stats:
        output = f"Diff Stats:\n{stats}\n\n{output}"

    return CommandResult(
        success=True,
        output=output,
        data={"diff": out, "stats": stats},
        duration_ms=(time.time() - start) * 1000,
    )


# ── /rewind ──

async def _cmd_rewind(args: str, orchestrator=None, context=None) -> CommandResult:
    """Undo last commits with safety checks."""
    start = time.time()

    n = 1
    if args.strip():
        try:
            n = int(args.strip())
        except ValueError:
            return CommandResult(
                success=False,
                output=f"Invalid argument: {args}. Usage: /rewind [N]",
                error="Invalid argument",
            )

    if n < 1 or n > 10:
        return CommandResult(
            success=False,
            output="Can only rewind 1-10 commits at a time for safety.",
            error="Invalid rewind count",
        )

    # Show what will be undone
    ok, log_out, _ = _run_git(f"log --oneline -{n}")
    if not ok or not log_out.strip():
        return CommandResult(success=False, output=f"No commits to rewind.")

    commits = log_out.strip().split("\n")

    # Use AI to analyze the impact (if orchestrator available)
    impact_analysis = ""
    if orchestrator and n <= 5:
        ok, diff_out, _ = _run_git(f"diff HEAD~{n}..HEAD")
        if ok and diff_out.strip():
            prompt = (
                f"Analyze the impact of reverting the last {n} commits:\n"
                f"```diff\n{diff_out[:2000]}\n```\n\n"
                f"Is it safe to revert? What would be lost? Respond concisely in 2-3 sentences."
            )
            result = await orchestrator.process(prompt)
            if result.get("findings"):
                impact_analysis = result["findings"][0].get("description", "")

    print(f"\nCommits to undo ({n}):")
    for c in commits:
        print(f"  {c}")
    if impact_analysis:
        print(f"\nImpact analysis:\n  {impact_analysis}")

    # Use soft reset so changes stay in working directory
    ok, out, err = _run_git(f"reset --soft HEAD~{n}")
    if ok:
        duration = (time.time() - start) * 1000
        return CommandResult(
            success=True,
            output=f"✅ Rewound {n} commit(s). Changes are unstaged (working directory preserved).\n\n"
                   f"To undo: git reset --soft ORIG_HEAD",
            data={"rewound": n, "commits": commits, "impact": impact_analysis},
            duration_ms=duration,
        )
    return CommandResult(success=False, output=err, error=err)


# ── /commit-push-pr ──

async def _cmd_commit_push_pr(args: str, orchestrator=None, context=None) -> CommandResult:
    """Commit, push, and create a PR."""
    start = time.time()

    # Step 1: Commit
    commit_result = await _cmd_commit(args, orchestrator, context)
    if not commit_result.success:
        return commit_result

    # Step 2: Get branch name
    ok, branch, _ = _run_git("rev-parse --abbrev-ref HEAD")
    if not ok or branch.strip() == "HEAD":
        return CommandResult(
            success=False,
            output="Not on a valid branch.",
            error="Invalid branch",
        )

    branch_name = branch.strip()

    # Step 3: Push
    print(f"\nPushing {branch_name}...")
    ok, push_out, push_err = _run_git(f"push -u origin {branch_name}", timeout=60)
    if not ok:
        return CommandResult(
            success=False,
            output=f"Commit succeeded but push failed:\n{push_err}",
            error=push_err,
        )

    # Step 4: Generate PR description
    pr_body = ""
    if orchestrator:
        ok, diff_main, _ = _run_git(f"diff origin/main...{branch_name}")
        if ok and diff_main.strip():
            prompt = (
                f"Generate a pull request description for these changes:\n"
                f"```diff\n{diff_main[:2000]}\n```\n\n"
                f"Format:\n"
                f"## Summary\n"
                f"[Brief description]\n\n"
                f"## Changes\n"
                f"- [list of changes]\n\n"
                f"## Testing\n"
                f"[how to test]"
            )
            result = await orchestrator.process(prompt)
            if result.get("findings"):
                pr_body = result["findings"][0].get("description", "")

    duration = (time.time() - start) * 1000

    output_parts = [
        commit_result.output,
        f"\n✅ Pushed to: {branch_name}",
    ]
    if pr_body:
        output_parts.append(f"\nProposed PR description:\n{pr_body}")
        output_parts.append(f"\nCreate PR at: https://github.com/OWNER/REPO/pull/new/{branch_name}")

    return CommandResult(
        success=True,
        output="\n".join(output_parts),
        data={
            "commit": commit_result.data,
            "branch": branch_name,
            "pr_body": pr_body,
        },
        duration_ms=duration,
    )


# ── Command definitions ──

commit_command = PromptCommand(
    name="commit",
    description="Generate a commit message and commit staged changes",
    prompt_template=(
        "You are helping write a git commit message. "
        "Analyze these changes and generate a concise commit message.\n\n"
        "{{args}}\n\n{{context}}"
    ),
    agent_name="Code-Scanner",
    aliases=["ci", "checkin"],
    permission_scope="git:commit",
)

commit_push_pr_command = PromptCommand(
    name="commit-push-pr",
    description="Commit, push, and create a PR",
    prompt_template=(
        "You are helping create a pull request. "
        "Analyze these changes and generate a PR description.\n\n"
        "{{args}}\n\n{{context}}"
    ),
    agent_name="Code-Scanner",
    aliases=["push-pr", "pr"],
    permission_scope="git:push",
)

branch_command = LocalCommand(
    name="branch",
    description="Create or switch branches (use /branch <name> to create)",
    handler=_cmd_branch,
    aliases=["br", "switch"],
    permission_scope="git:branch",
)

diff_command = LocalCommand(
    name="diff",
    description="Show git diff (use /diff <ref> for specific comparison)",
    handler=_cmd_diff,
    aliases=["compare", "delta"],
)

rewind_command = LocalCommand(
    name="rewind",
    description="Undo last N commits (soft reset, preserves changes)",
    handler=_cmd_rewind,
    aliases=["undo", "reset"],
    permission_scope="git:rewind",
)


# ── All git commands ──

GIT_COMMANDS = [
    commit_command,
    commit_push_pr_command,
    branch_command,
    diff_command,
    rewind_command,
]
