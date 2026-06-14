"""
Diagnostic Slash Commands — Ported from Claude Code's diagnostic commands.

Commands:
  /doctor     — Run system diagnostics and health checks
  /cost       — Show token usage and cost estimates
  /version    — Show version information
  /stats      — Show system statistics and performance metrics
"""

import time
import os
import platform
import sys
from typing import Optional, Dict, Any

from src.commands.base import (
    Command, CommandResult, CommandType,
    LocalCommand,
)

SENTINEL_VERSION = "2.3.0"
SENTINEL_BUILD = "fable5-edition"


# ── /doctor ──

async def _cmd_doctor(args: str, orchestrator=None, context=None) -> CommandResult:
    """Run system diagnostics and health checks."""
    start = time.time()

    checks = []

    # 1. Python version
    py_ver = sys.version
    py_ok = sys.version_info >= (3, 10)
    checks.append(("Python", f"{py_ver.split()[0]}", py_ok))

    # 2. Git availability
    try:
        import subprocess
        result = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=5)
        git_ok = result.returncode == 0
        git_ver = result.stdout.strip() if git_ok else "not found"
    except Exception:
        git_ok = False
        git_ver = "not found"
    checks.append(("Git", git_ver, git_ok))

    # 3. Docker availability
    try:
        import subprocess
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
        docker_ok = result.returncode == 0
        docker_ver = result.stdout.strip() if docker_ok else "not found"
    except Exception:
        docker_ok = False
        docker_ver = "not found"
    checks.append(("Docker", docker_ver, docker_ok))

    # 4. Orchestrator subsystems (if available)
    if orchestrator:
        ts = orchestrator.thinking_engine.get_status()
        sf = orchestrator.safety_classifier.get_status()
        ctx = orchestrator.context_manager.get_status()
        mem = orchestrator.memory.get_status()
        ce = orchestrator.code_executor.get_status()

        checks.append(("Thinking Engine", f"effort={ts['effort']}", True))
        checks.append(("Safety Classifier", f"{sf['total_rules']} rules", sf['enabled']))
        checks.append(("Context Manager", f"{ctx['usage_ratio']:.0%} used", True))
        checks.append(("Memory System", f"{mem.get('state', {}).get('project_entries', 0)} entries", True))
        checks.append(("Code Sandbox", "Docker" if ce.get('docker_available') else "Local", True))

    # 5. Rich availability
    try:
        import rich
        rich_ok = True
        rich_ver = rich.__version__
    except ImportError:
        rich_ok = False
        rich_ver = "not installed"
    checks.append(("Rich (UI)", rich_ver, rich_ok))

    # 6. Disk space (cwd)
    try:
        import shutil
        total, used, free = shutil.disk_usage(os.getcwd())
        free_gb = free / (1024**3)
        disk_ok = free_gb > 1.0
        checks.append(("Disk Free", f"{free_gb:.1f} GB", disk_ok))
    except Exception:
        checks.append(("Disk Free", "unknown", False))

    # Format output
    lines = ["🏥 Sentinel Doctor — System Diagnostics:", ""]
    all_ok = True
    for name, value, ok in checks:
        icon = "✅" if ok else "❌"
        lines.append(f"  {icon} {name:<20} {value}")
        if not ok:
            all_ok = False

    lines.append("")
    if all_ok:
        lines.append("  ✅ All systems operational.")
    else:
        lines.append("  ⚠️ Some checks failed. Review above for details.")

    return CommandResult(
        success=all_ok,
        output="\n".join(lines),
        data={"checks": [{"name": n, "value": v, "ok": o} for n, v, o in checks]},
        duration_ms=(time.time() - start) * 1000,
    )


# ── /cost ──

async def _cmd_cost(args: str, orchestrator=None, context=None) -> CommandResult:
    """Show token usage and cost estimates."""
    start = time.time()

    lines = ["💰 Token Usage & Cost:", ""]

    if orchestrator:
        ctx = orchestrator.context_manager.get_status()
        history = orchestrator.get_history()

        total_processed = ctx.get("total_tokens_processed", 0)
        current_used = ctx.get("current_tokens", 0)
        max_ctx = ctx.get("max_context_tokens", 1_000_000)

        # Estimate costs (based on Claude API rates)
        input_cost_per_1k = 0.003  # $ per 1K input tokens
        output_cost_per_1k = 0.015  # $ per 1K output tokens
        estimated_input_cost = (total_processed / 1000) * input_cost_per_1k
        estimated_output_cost = (current_used / 1000) * output_cost_per_1k

        lines.append(f"  Total tokens processed:  {total_processed:,}")
        lines.append(f"  Current context usage:   {current_used:,} / {max_ctx:,}")
        lines.append(f"  Context utilization:     {ctx.get('usage_ratio', 0):.1%}")
        lines.append(f"  Compactions performed:   {ctx.get('compaction_count', 0)}")
        lines.append(f"")
        lines.append(f"  Estimated cost (input):  ${estimated_input_cost:.4f}")
        lines.append(f"  Estimated cost (output): ${estimated_output_cost:.4f}")
        lines.append(f"  Estimated total:         ${estimated_input_cost + estimated_output_cost:.4f}")
        lines.append(f"")
        lines.append(f"  Tasks completed:         {len(history)}")
        lines.append(f"  Active task budgets:     {ctx.get('active_task_budgets', 0)}")
    else:
        lines.append("  Orchestrator not available.")

    lines.append(f"")
    lines.append(f"  Note: Costs are estimates. Actual costs depend on model used.")

    return CommandResult(
        success=True,
        output="\n".join(lines),
        data={"total_tokens_processed": total_processed if orchestrator else 0},
        duration_ms=(time.time() - start) * 1000,
    )


# ── /version ──

async def _cmd_version(args: str, orchestrator=None, context=None) -> CommandResult:
    """Show version information."""
    lines = [
        f"📦 Sentinel Cyber AI v{SENTINEL_VERSION}",
        f"  Build: {SENTINEL_BUILD}",
        f"  Python: {sys.version.split()[0]}",
        f"  Platform: {platform.system()} {platform.release()}",
        f"  Architecture: {platform.machine()}",
        f"",
        f"  Features:",
        f"    • Slash Command System (port of Claude Code)",
        f"    • MCP Server (Model Context Protocol)",
        f"    • Permission System (fine-grained tool access)",
        f"    • Adaptive Thinking (effort: low/medium/high/max)",
        f"    • Multi-Agent Architecture (6 specialized agents)",
        f"    • Self-Play Learning Pipeline",
        f"    • Neural Threat Detection",
        f"    • Supply Chain Analyzer",
        f"    • Quantum Crypto Scanner",
        f"    • Real-Time WebSocket Dashboard",
    ]
    return CommandResult(
        success=True,
        output="\n".join(lines),
        data={"version": SENTINEL_VERSION, "build": SENTINEL_BUILD},
    )


# ── /stats ──

async def _cmd_stats(args: str, orchestrator=None, context=None) -> CommandResult:
    """Show system statistics and performance metrics."""
    start = time.time()

    lines = ["📊 Sentinel Statistics:", ""]

    if orchestrator:
        history = orchestrator.get_history(limit=100)
        total_tasks = len(history)
        successful = sum(1 for t in history if t.get("synthesis", {}).get("status") == "success")
        total_findings = sum(
            len(t.get("synthesis", {}).get("findings", []))
            for t in history
        )

        # Agent performance
        agent_stats = {}
        for t in history:
            for ar in t.get("results", []):
                name = ar.get("agent_name", "unknown")
                if name not in agent_stats:
                    agent_stats[name] = {"calls": 0, "total_duration": 0}
                agent_stats[name]["calls"] += 1
                agent_stats[name]["total_duration"] += ar.get("duration_ms", 0)

        lines.append(f"  Total tasks completed:   {total_tasks}")
        lines.append(f"  Successful tasks:        {successful} ({successful/max(total_tasks,1):.0%})")
        lines.append(f"  Total findings:          {total_findings}")
        lines.append(f"")

        if agent_stats:
            lines.append(f"  Agent Performance:")
            for name, stats in sorted(agent_stats.items()):
                avg_duration = stats["total_duration"] / stats["calls"] if stats["calls"] > 0 else 0
                lines.append(f"    {name:<20} {stats['calls']} calls, avg {avg_duration:.0f}ms")

        # Subsystem status
        lines.append(f"")
        lines.append(f"  Subsystems:")
        ts = orchestrator.thinking_engine.get_status()
        lines.append(f"    Thinking: {ts['history_count']} sessions (effort: {ts['effort']})")

        mem = orchestrator.memory.get_status()
        mem_entries = sum(mem.get("state", {}).get(k, 0) for k in ["system_entries", "project_entries", "session_entries"])
        lines.append(f"    Memory: {mem_entries} entries total")
    else:
        lines.append("  Orchestrator not available.")

    return CommandResult(
        success=True,
        output="\n".join(lines),
        data={},
        duration_ms=(time.time() - start) * 1000,
    )


# ── Command definitions ──

doctor_command = LocalCommand(
    name="doctor",
    description="Run system diagnostics and health checks",
    handler=_cmd_doctor,
    aliases=["health", "diagnose", "checkup"],
)

cost_command = LocalCommand(
    name="cost",
    description="Show token usage and cost estimates",
    handler=_cmd_cost,
    aliases=["pricing", "usage", "tokens"],
)

version_command = LocalCommand(
    name="version",
    description="Show version information",
    handler=_cmd_version,
    aliases=["v", "--version", "ver", "info"],
)

stats_command = LocalCommand(
    name="stats",
    description="Show system statistics and performance metrics",
    handler=_cmd_stats,
    aliases=["metrics", "performance", "perf"],
)


# ── All diagnostic commands ──

DIAGNOSTIC_COMMANDS = [
    doctor_command,
    cost_command,
    version_command,
    stats_command,
]
