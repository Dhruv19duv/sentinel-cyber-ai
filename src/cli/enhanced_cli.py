"""Enhanced CLI — Rich terminal output for the Sentinel platform.

Provides colored output, tables, progress bars, and interactive elements
using the `rich` library. Falls back gracefully to plain text if rich is
not installed.
"""

import sys
import os
import time
from typing import Dict, List, Optional, Any, Callable

# Try to import rich for enhanced output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.markdown import Markdown
    from rich.tree import Tree
    from rich import box
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False


class SentinelCLI:
    """Enhanced CLI with rich output formatting."""

    @staticmethod
    def print_header(text: str):
        """Print a colored header."""
        if HAS_RICH:
            console.print(f"\n[bold cyan]{'=' * 60}[/]")
            console.print(f"[bold green]{text}[/]")
            console.print(f"[bold cyan]{'=' * 60}[/]\n")
        else:
            print(f"\n{'=' * 60}")
            print(f"  {text}")
            print(f"{'=' * 60}\n")

    @staticmethod
    def print_analysis_result(result: Dict[str, Any]):
        """Print analysis results in a formatted table."""
        if HAS_RICH:
            # Status header
            status = result.get("status", "unknown")
            status_color = "green" if status == "success" else "yellow" if status == "partial" else "red"
            task_id = result.get("task_id", "N/A")

            console.print(Panel(
                f"[bold]Status:[/] [{status_color}]{status.upper()}[/]  "
                f"[bold]Confidence:[/] {result.get('confidence', 0):.1%}  "
                f"[bold]Task ID:[/] {task_id}\n"
                f"[bold]Summary:[/] {result.get('summary', 'N/A')}\n"
                f"[bold]Agents:[/] {', '.join(result.get('agents_used', []))}",
                title="🔐 Sentinel Analysis",
                border_style="cyan",
            ))

            # Findings table
            findings = result.get("findings", [])
            if findings:
                table = Table(title=f"Findings ({len(findings)})", box=box.ROUNDED)
                table.add_column("#", style="dim", width=3)
                table.add_column("Severity", width=10)
                table.add_column("Title", width=40)
                table.add_column("Description", width=60)

                for i, f in enumerate(findings, 1):
                    severity = f.get("severity", "INFO")
                    sev_style = {
                        "CRITICAL": "bold red",
                        "HIGH": "orange1",
                        "MEDIUM": "yellow",
                        "LOW": "cyan",
                    }.get(severity, "white")
                    table.add_row(
                        str(i),
                        f"[{sev_style}]{severity}[/]",
                        f.get("title", "N/A")[:40],
                        f.get("description", "")[:60],
                    )
                console.print(table)
            else:
                console.print("[green]✅ No vulnerabilities found![/]")

            # Agent details
            agent_results = result.get("agent_results", [])
            if agent_results:
                console.print("\n[bold]Agent Details:[/]")
                for ar in agent_results:
                    status_icon = "✅" if ar.get("status") == "success" else "❌"
                    console.print(
                        f"  {status_icon} [bold]{ar.get('agent_name')}[/]: "
                        f"{ar.get('status')} "
                        f"(confidence: {ar.get('confidence', 0):.0%})"
                    )
        else:
            # Fallback to plain text
            print(f"\n{'='*60}")
            print(f"🔐 Sentinel Analysis — {result.get('task_id', 'N/A')}")
            print(f"{'='*60}")
            print(f"Status: {result.get('status', 'unknown').upper()}")
            print(f"Confidence: {result.get('confidence', 0):.1%}")
            print(f"Summary: {result.get('summary', 'N/A')}")
            print(f"Agents: {', '.join(result.get('agents_used', []))}")
            print()

            findings = result.get("findings", [])
            if findings:
                print(f"Findings ({len(findings)}):")
                for f in findings:
                    severity = f.get("severity", "INFO")
                    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                    print(f"\n{icon} **{f.get('title', 'N/A')}** [{severity}]")
                    print(f"   {f.get('description', '')[:200]}")

    @staticmethod
    def print_benchmark_results(results: Dict[str, Any]):
        """Print benchmark results with charts."""
        if HAS_RICH:
            console.print(Panel(
                f"[bold]Success Rate:[/] {results.get('success_rate', 0):.0%}  "
                f"[bold]Passed:[/] [green]{results.get('passed', 0)}[/]  "
                f"[bold]Failed:[/] [red]{results.get('failed', 0)}[/]\n"
                f"[bold]Avg Confidence:[/] {results.get('average_confidence', 0):.0%}  "
                f"[bold]Avg Detection:[/] {results.get('average_detection_rate', 0):.0%}",
                title="📊 Benchmark Results",
                border_style="green",
            ))

            # By category
            categories = results.get("by_category", {})
            if categories:
                table = Table(title="By Category", box=box.SIMPLE)
                table.add_column("Category", style="cyan")
                table.add_column("Passed", style="green")
                table.add_column("Total", style="white")
                table.add_column("Rate", style="yellow")

                for cat, data in categories.items():
                    rate = data["passed"] / data["total"] if data["total"] > 0 else 0
                    table.add_row(
                        cat.replace("_", " ").title(),
                        str(data["passed"]),
                        str(data["total"]),
                        f"{rate:.0%}",
                    )
                console.print(table)

            # By difficulty
            difficulties = results.get("by_difficulty", {})
            if difficulties:
                table = Table(title="By Difficulty", box=box.SIMPLE)
                table.add_column("Difficulty", style="cyan")
                table.add_column("Passed", style="green")
                table.add_column("Total", style="white")
                table.add_column("Rate", style="yellow")

                for diff, data in difficulties.items():
                    rate = data["passed"] / data["total"] if data["total"] > 0 else 0
                    table.add_row(diff.title(), str(data["passed"]), str(data["total"]), f"{rate:.0%}")
                console.print(table)
        else:
            print(f"\nBenchmark Results:")
            print(f"  Success Rate: {results.get('success_rate', 0):.0%}")
            print(f"  Passed: {results.get('passed', 0)}/{results.get('total_tests', 0)}")
            print(f"  Avg Confidence: {results.get('average_confidence', 0):.0%}")

    @staticmethod
    def print_agent_status(agents: List[Dict[str, Any]]):
        """Print agent status table."""
        if HAS_RICH:
            table = Table(title="🤖 Agent Status", box=box.ROUNDED)
            table.add_column("Agent", style="cyan", no_wrap=True)
            table.add_column("Model", style="magenta")
            table.add_column("Tools", style="white")
            table.add_column("Status", style="green")

            for agent in agents:
                table.add_row(
                    agent.get("name", "N/A"),
                    agent.get("model", "N/A"),
                    ", ".join(agent.get("tools", [])[:3]),
                    "🟢 Active",
                )
            console.print(table)
        else:
            print("\nRegistered Agents:")
            for agent in agents:
                print(f"  • {agent.get('name')} ({agent.get('model')})")

    @staticmethod
    def print_finding_detail(finding: Dict[str, Any]):
        """Print a single finding with rich formatting."""
        severity = finding.get("severity", "INFO")
        sv = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "⚪")

        if HAS_RICH:
            console.print(Panel(
                f"[bold]{finding.get('title', 'Finding')}[/] [{severity}]\n\n"
                f"{finding.get('description', '')}\n\n"
                + (f"[bold]💊 Remediation:[/] {finding.get('remediation', '')}\n" if finding.get('remediation') else "")
                + (f"[bold]📋 CWE:[/] {finding.get('cwe', 'N/A')}\n" if finding.get('cwe') else "")
                + (f"[bold]📍 Location:[/] {finding.get('location', 'N/A')}" if finding.get('location') else ""),
                title=f"{sv} Finding",
                border_style="red" if severity == "CRITICAL" else "orange1" if severity == "HIGH" else "yellow",
            ))
        else:
            print(f"\n{sv} **{finding.get('title')}** [{severity}]")
            print(f"   {finding.get('description', '')[:200]}")
            if finding.get("remediation"):
                print(f"   💊 Fix: {finding['remediation'][:150]}")

    @staticmethod
    def progress_spinner(message: str = "Processing..."):
        """Create a progress spinner context manager."""
        if HAS_RICH:
            return Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
            )
        else:
            return _NullProgress()

    @staticmethod
    def print_code(code: str, language: str = "python"):
        """Print code with syntax highlighting."""
        if HAS_RICH:
            console.print(Syntax(code, language, theme="monokai", line_numbers=True))
        else:
            print(f"```{language}")
            print(code)
            print("```")

    @staticmethod
    def print_tree(structure: Dict[str, Any], label: str = "Project"):
        """Print a directory tree."""
        if HAS_RICH:
            tree = Tree(f"[bold cyan]{label}[/]")
            _build_tree(tree, structure)
            console.print(tree)
        else:
            def _print_flat(d, indent=0):
                for k, v in d.items():
                    print(f"{'  ' * indent}{'📁 ' if isinstance(v, dict) else '📄 '}{k}")
                    if isinstance(v, dict):
                        _print_flat(v, indent + 1)
            _print_flat(structure)

    @staticmethod
    def confirm_action(message: str) -> bool:
        """Ask for user confirmation."""
        if HAS_RICH:
            return console.input(f"[bold yellow]{message}[/] (y/N): ").lower() == "y"
        else:
            return input(f"{message} (y/N): ").lower() == "y"

    @staticmethod
    def print_error(message: str):
        """Print an error message."""
        if HAS_RICH:
            console.print(f"[bold red]❌ Error:[/] {message}")
        else:
            print(f"❌ Error: {message}")

    @staticmethod
    def print_warning(message: str):
        """Print a warning message."""
        if HAS_RICH:
            console.print(f"[bold yellow]⚠️  {message}[/]")
        else:
            print(f"⚠️  {message}")

    @staticmethod
    def print_success(message: str):
        """Print a success message."""
        if HAS_RICH:
            console.print(f"[bold green]✅ {message}[/]")
        else:
            print(f"✅ {message}")

    @staticmethod
    def print_info(message: str):
        """Print an info message."""
        if HAS_RICH:
            console.print(f"[cyan]ℹ️  {message}[/]")
        else:
            print(f"ℹ️  {message}")


class _NullProgress:
    """Fallback progress indicator when rich is not available."""

    def __enter__(self):
        print("⏳ Processing...", end="", flush=True)
        return self

    def __exit__(self, *args):
        print("\r" + " " * 40 + "\r", end="", flush=True)

    def add_task(self, *args, **kwargs):
        pass

    def update(self, *args, **kwargs):
        pass


def _build_tree(tree, structure: Dict):
    """Recursively build a rich tree from a dict structure."""
    for key, value in structure.items():
        if isinstance(value, dict):
            branch = tree.add(f"[bold cyan]📁 {key}[/]")
            _build_tree(branch, value)
        else:
            tree.add(f"📄 {key}  [dim]{value}[/]")
