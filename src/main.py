"""
Sentinel Cyber AI — Main Entry Point.

The command center for the enterprise multi-agent cybersecurity platform.
Initializes the orchestrator, registers all specialized agents, and provides
both CLI and API interfaces.

Usage:
    python -m src.main analyze "find vulns in this code: ..."
    python -m src.main think "analyze this code" --effort max
    python -m src.main sandbox --python "print('hello')"
    python -m src.main memory --status
    python -m src.main safety "check this query"
    python -m src.main vision path/to/image.png
"""

import asyncio
import argparse
import logging
import os
import sys
from typing import Optional

# Fix Windows terminal encoding for emoji support
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel")


# ── Sentry Initialization (CLI) ──
def init_sentry():
    """Initialize Sentry SDK for CLI usage if SENTRY_DSN is configured."""
    dsn = os.environ.get("SENTRY_DSN")
    if not dsn:
        return False

    try:
        import sentry_sdk
        from sentry_sdk.integrations.logging import LoggingIntegration

        environment = os.environ.get("SENTINEL_ENV", "development")
        release = os.environ.get("SENTINEL_VERSION", "latest")

        sentry_sdk.init(
            dsn=dsn,
            environment=environment,
            release=release,
            integrations=[
                LoggingIntegration(level=logging.WARNING, event_level=logging.ERROR),
            ],
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0.1")),
            send_default_pii=False,
            attach_stacktrace=True,
        )
        logger.info(f"Sentry initialized for CLI (env={environment})")
        return True
    except ImportError:
        logger.debug("sentry-sdk not installed — skipping Sentry init")
        return False


def setup_orchestrator():
    """Initialize the orchestrator with all specialized agents.

    Fable 5 Feature Parity — Now includes:
    - Adaptive Thinking Engine (effort parameter: low/medium/high/max)
    - Code Execution Sandbox (Docker-based with Python 3.11)
    - Persistent Memory System (tiered memory with compaction)
    - Context Manager (1M token context window)
    - Safety Classifier + Fallback (refusal system)
    - Vision Agent (multimodal analysis)
    - Agentic Planning (long-horizon task decomposition)
    - Codebase RAG (large codebase reasoning)
    - Scientific Analysis (biology/healthcare)
    - 5 specialized security agents
    """
    from src.agents.orchestrator import Orchestrator
    from src.agents.scanner_agent import CodeScannerAgent
    from src.agents.exploit_agent import ExploitAnalyzerAgent
    from src.agents.patch_agent import PatchGeneratorAgent
    from src.agents.analysis_agent import ThreatIntelligenceAgent
    from src.agents.report_agent import ReportGeneratorAgent
    from src.science.scientific_agent import ScientificAnalysisAgent

    orchestrator = Orchestrator()

    # Register all specialized agents
    orchestrator.register_agent(CodeScannerAgent(model_name="qwen3-235b"))
    orchestrator.register_agent(ExploitAnalyzerAgent(model_name="deepseek-r1-671b"))
    orchestrator.register_agent(PatchGeneratorAgent(model_name="mistral-large-675b"))
    orchestrator.register_agent(ThreatIntelligenceAgent(model_name="qwen3-235b"))
    orchestrator.register_agent(ReportGeneratorAgent(model_name="qwen3-235b"))
    orchestrator.register_agent(ScientificAnalysisAgent(model_name="qwen3-235b"))

    # ═══ Register Slash Commands (Claude Code feature port) ═══
    orchestrator.register_all_commands()
    # ════════════════════════════════════════════════════════════

    logger.info(
        f"Orchestrator ready with {len(orchestrator.registered_agents)} agents: "
        f"{', '.join(orchestrator.registered_agents)}"
    )
    logger.info(
        f"Slash commands available: {len(orchestrator.command_registry)}"
    )
    return orchestrator


async def cmd_analyze(orchestrator, query: str, output_format: str = "text"):
    """Analyze a security query through the multi-agent system."""
    result = await orchestrator.process(query)

    if output_format == "json":
        import json
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"\n{'='*60}")
        print(f"Sentinel Analysis -- {result.get('task_id', 'N/A')}")
        print(f"{'='*60}")
        print(f"Status: {result.get('status', 'unknown').upper()}")
        print(f"Confidence: {result.get('confidence', 0):.1%}")
        print(f"Summary: {result.get('summary', 'N/A')}")
        print(f"Agents: {', '.join(result.get('agents_used', []))}")

        # Fable 5 thinking info
        thinking = result.get("thinking", {})
        if thinking:
            print(f"Thinking Effort: {thinking.get('effort', 'N/A')}")
            print(f"Thinking Tokens: {thinking.get('tokens', 0)}")

        # Context info
        ctx = result.get("context", {})
        if ctx:
            print(f"Context Usage: {ctx.get('usage_ratio', 0):.0%} of 1M tokens")
        print()

        findings = result.get("findings", [])
        if findings:
            print(f"Findings ({len(findings)}):")
            print("-" * 60)
            for i, finding in enumerate(findings, 1):
                severity = finding.get("severity", "INFO")
                print(f"\n  [{severity}] {finding.get('title', f'Issue {i}')}")
                print(f"     {finding.get('description', '')[:300]}")
                if finding.get("remediation"):
                    print(f"     Fix: {finding['remediation'][:200]}")
                if finding.get("cwe"):
                    print(f"     CWE: {finding['cwe']}")
        else:
            print("No findings.")

        if result.get("agent_results"):
            print(f"\n{'='*60}")
            print("Agent Details:")
            for ar in result["agent_results"]:
                print(f"  o {ar['agent_name']}: {ar['status']} ({ar.get('confidence', 0):.0%})")
                print(f"    {ar.get('summary', '')[:150]}")

    return result


async def cmd_think(orchestrator, query: str, effort: str = "high"):
    """Run adaptive thinking with configurable effort.

    Matches Fable 5's Adaptive Thinking with effort parameter.
    """
    engine = orchestrator.thinking_engine
    engine.set_effort(effort)

    result = await engine.think(query)

    print(f"\n{'='*60}")
    print(f"Adaptive Thinking Result")
    print(f"{'='*60}")
    print(f"Effort: {result.effort_used.value}")
    print(f"Thinking Time: {result.thinking_time_ms:.0f}ms")
    print(f"Total Thinking Tokens: {result.total_thinking_tokens}")
    print(f"Interleaved Steps: {result.interleaved_steps}")
    print()

    print("Thinking Blocks:")
    print("-" * 60)
    for i, block in enumerate(result.thinking_blocks, 1):
        print(f"\n  [{block.type}] (effort: {block.effort_used.value})")
        print(f"  {block.content[:500]}")
    print()

    print("Response Guidance:")
    print("-" * 60)
    print(f"  {result.final_response[:500]}")

    return result


async def cmd_sandbox_python(orchestrator, code: str):
    """Execute Python code in the sandbox.

    Matches Fable 5's code execution tool.
    """
    executor = orchestrator.code_executor
    result = await executor.execute_python(code)

    print(f"\n{'='*60}")
    print(f"Sandboxed Code Execution")
    print(f"{'='*60}")
    print(f"Success: {result.success}")
    print(f"Exit Code: {result.exit_code}")
    print(f"Execution Time: {result.execution_time_ms:.0f}ms")
    print()

    if result.stdout:
        print("STDOUT:")
        print("-" * 40)
        print(result.stdout[:2000])
    if result.stderr:
        print("STDERR:")
        print("-" * 40)
        print(result.stderr[:1000])
    if result.files_created:
        print(f"Files Created: {', '.join(result.files_created)}")

    return result


async def cmd_sandbox_bash(orchestrator, command: str):
    """Execute a bash command in the sandbox.

    Matches Fable 5's bash sub-tool.
    """
    executor = orchestrator.code_executor
    result = await executor.execute_bash(command)

    print(f"\n{'='*60}")
    print(f"Sandboxed Bash Execution")
    print(f"{'='*60}")
    print(f"Success: {result.success}")
    print(f"Exit Code: {result.exit_code}")
    print(f"Execution Time: {result.execution_time_ms:.0f}ms")
    print()

    if result.stdout:
        print("STDOUT:")
        print("-" * 40)
        print(result.stdout[:2000])
    if result.stderr:
        print("STDERR:")
        print("-" * 40)
        print(result.stderr[:1000])

    return result


async def cmd_memory_status(orchestrator):
    """Show memory system status."""
    memory = orchestrator.memory
    status = memory.get_status()
    context = memory.get_compressed_context()

    print(f"\n{'='*60}")
    print(f"Memory Status")
    print(f"{'='*60}")
    for key, value in status.items():
        if isinstance(value, dict):
            print(f"\n{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"{key}: {value}")
    print()
    print(f"Compressed Context ({len(context.split())} words):")
    print("-" * 40)
    print(context[:1000])


async def cmd_memory_add(orchestrator, content: str, tags: Optional[str] = None):
    """Add a memory entry."""
    memory = orchestrator.memory
    tag_list = tags.split(",") if tags else ["manual"]
    entry = memory.add_project_entry(content, tags=tag_list)
    print(f"\nAdded memory entry: {entry.id}")
    print(f"Type: {entry.entry_type}")
    print(f"Tags: {', '.join(entry.tags)}")


async def cmd_memory_compact(orchestrator):
    """Compact session memory."""
    memory = orchestrator.memory
    result = await memory.compact_async()
    print(f"\nCompaction Result:")
    for key, value in result.items():
        print(f"  {key}: {value}")


async def cmd_context_status(orchestrator):
    """Show context manager status."""
    cm = orchestrator.context_manager
    status = cm.get_status()

    print(f"\n{'='*60}")
    print(f"Context Manager Status (Fable 5 1M Token Window)")
    print(f"{'='*60}")
    print(f"Max Context: {status['max_context_tokens']:,} tokens")
    print(f"Max Output:  {status['max_output_tokens']:,} tokens")
    print(f"Current:     {status['current_tokens']:,} tokens")
    print(f"Available:   {status['available_tokens']:,} tokens")
    print(f"Usage:       {status['usage_ratio']:.1%}")
    print(f"Blocks:      {status['blocks_count']}")
    print(f"Compactions: {status['compaction_count']}")
    print(f"Task Budgets: {status['active_task_budgets']}")
    print()
    if status['blocks_by_type']:
        print("Blocks by type:")
        for btype, count in status['blocks_by_type'].items():
            print(f"  {btype}: {count}")
    print(f"\nStrategy: {status['config']['strategy']}")
    print(f"Context Editing: {status['config']['context_editing']}")

    # Visual bar
    usage = status['usage_ratio']
    bar_len = 40
    filled = int(bar_len * usage)
    bar = "=" * filled + "-" * (bar_len - filled)
    print(f"\n[Context: {bar}] {usage:.1%}")


async def cmd_safety_check(orchestrator, content: str):
    """Check content against safety classifiers.

    Matches Fable 5's safety classifier system.
    """
    classifier = orchestrator.safety_classifier
    result = classifier.classify(content)

    print(f"\n{'='*60}")
    print(f"Safety Classification Result")
    print(f"{'='*60}")
    print(f"Is Safe: {result.is_safe}")
    print(f"Stop Reason: {result.stop_reason}")
    if result.refusal_reason:
        print(f"Refusal Reason: {result.refusal_reason.value}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Severity: {result.severity}")
    print()
    if result.matched_patterns:
        print("Matched Patterns:")
        for p in result.matched_patterns:
            print(f"  - {p}")
    if result.suggested_action:
        print(f"\nSuggested Action: {result.suggested_action}")
    print(f"Fallback Available: {result.fallback_available}")

    if result.fallback_available:
        fallback = orchestrator.fallback_manager.get_fallback_model(
            "primary", result.refusal_reason
        )
        if fallback:
            print(f"Fallback Model: {fallback}")

    return result


async def cmd_vision(orchestrator, path: str):
    """Analyze an image with the vision agent.

    Matches Fable 5's vision/multimodal capabilities.
    """
    agent = orchestrator.vision_agent
    result = agent.analyze_image_file(path)

    print(f"\n{'='*60}")
    print(f"Vision Analysis")
    print(f"{'='*60}")
    if result.error:
        print(f"Error: {result.error}")
        return result

    print("Image Metadata:")
    for key, value in result.image_metadata.items():
        print(f"  {key}: {value}")
    print()

    if result.analysis:
        print(f"Analysis: {result.analysis}")
        print()

    if result.detected_text:
        print("Detected Text:")
        print("-" * 40)
        print(result.detected_text[:1000])
        print()

    if result.code_fragments:
        print(f"Code Fragments ({len(result.code_fragments)}):")
        for frag in result.code_fragments:
            print(f"  [{frag['language']}] {frag['code'][:100]}...")

    return result


async def cmd_scan(orchestrator, path: str):
    """Scan a codebase for vulnerabilities using all agents."""
    import os
    import glob

    if not os.path.exists(path):
        logger.error(f"Path not found: {path}")
        return

    logger.info(f"Scanning: {path}")

    extensions = ["*.py", "*.js", "*.ts", "*.java", "*.go", "*.rs", "*.cpp", "*.c", "*.php", "*.rb"]
    files = []
    for ext in extensions:
        files.extend(glob.glob(os.path.join(path, "**", ext), recursive=True))

    logger.info(f"Found {len(files)} source files to analyze")

    all_findings = []
    batch_size = 5
    for i in range(0, len(files), batch_size):
        batch = files[i:i + batch_size]
        tasks = []
        for filepath in batch:
            try:
                with open(filepath, "r", errors="ignore") as f:
                    code = f.read()
                query = f"Analyze this code for vulnerabilities:\n```\n{code[:2000]}\n```"
                tasks.append(orchestrator.process(query))
            except Exception as e:
                logger.warning(f"Could not read {filepath}: {e}")

        if tasks:
            results = await asyncio.gather(*tasks)
            for result in results:
                all_findings.extend(result.get("findings", []))

    critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")

    print(f"\n{'='*60}")
    print(f"Scan Complete: {path}")
    print(f"{'='*60}")
    print(f"Files analyzed: {len(files)}")
    print(f"Total findings: {len(all_findings)}")
    print(f"  Critical: {critical}")
    print(f"  High:     {high}")
    print(f"  Medium:   {medium}")


async def cmd_interactive(orchestrator):
    """Interactive CLI mode with Fable 5 features."""
    print(f"\n{'='*60}")
    print("Sentinel Cyber AI — Interactive Mode (Fable 5 + Claude Code Features)")
    print(f"{'='*60}")
    print("Slash Commands (Claude Code port):")
    print("  /review <code>        — Analyze code for issues")
    print("  /commit               — Generate AI commit message and commit")
    print("  /memory               — View/manage persistent memory")
    print("  /doctor               — Run system diagnostics")
    print("  /help                 — Show slash command list")
    print("  /cost                 — Show token usage and cost")
    print("  /config key=value     — Modify configuration")
    print("  /permissions list     — View permission rules")
    print("  /version              — Show version info")
    print()
    print("Native Commands:")
    print("  analyze <query>       — Analyze a security query")
    print("  think <query>         — Run adaptive thinking (--effort <level>)")
    print("  python <code>         — Execute Python in sandbox")
    print("  bash <command>        — Execute bash in sandbox")
    print("  memory [status|add|compact] — Memory management")
    print("  context               — Show context window status")
    print("  safety <content>      — Check against safety classifiers")
    print("  vision <path>         — Analyze an image")
    print("  scan <path>           — Scan a codebase")
    print("  agents                — List registered agents")
    print("  fable-status          — Show all subsystems status")
    print("  help                  — Show this help")
    print("  quit                  — Exit")
    print()

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not line:
            continue

        if line.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break

        if line.lower() == "agents":
            print(f"\nRegistered agents ({len(orchestrator.registered_agents)}):")
            for name in orchestrator.registered_agents:
                agent = orchestrator.get_agent(name)
                print(f"  o {name} ({agent.model_name})")
            print()
            continue

        if line.lower() == "fable-status":
            # Show all Fable 5 subsystems
            ts = orchestrator.thinking_engine.get_status()
            ce = orchestrator.code_executor.get_status()
            mem = orchestrator.memory.get_status()
            ctx = orchestrator.context_manager.get_status()
            sf = orchestrator.safety_classifier.get_status()
            vi = orchestrator.vision_agent.get_status()

            print(f"\n{'='*60}")
            print("Fable 5 Feature Parity — All Subsystems")
            print(f"{'='*60}")
            print(f"\n1. Adaptive Thinking Engine")
            print(f"   Effort: {ts['effort']}")
            print(f"   Interleaved: {ts['interleaved_thinking']}")
            print(f"   History: {ts['history_count']} thinking sessions")
            print(f"\n2. Code Execution Sandbox")
            print(f"   Docker: {'Available' if ce['docker_available'] else 'Not available'}")
            print(f"   Active Sessions: {ce['active_sessions']}")
            print(f"   Resources: {ce['config']['memory_mb']}MB RAM, {ce['config']['cpu_count']} CPU")
            print(f"\n3. Persistent Memory")
            print(f"   Directory: {mem['memory_dir']}")
            print(f"   System: {mem['state']['system_entries']} entries")
            print(f"   Project: {mem['state']['project_entries']} entries")
            print(f"   Session: {mem['state']['session_entries']} entries")
            print(f"   Pinned: {mem['state']['pinned_entries']} entries")
            print(f"   Token Budget: {mem.get('compaction_threshold', 'N/A')}")
            print(f"\n4. Context Manager (1M tokens)")
            print(f"   Usage: {ctx['usage_ratio']:.1%} ({ctx['current_tokens']:,}/{ctx['max_context_tokens']:,})")
            print(f"   Output Limit: {ctx['max_output_tokens']:,} tokens")
            print(f"   Compactions: {ctx['compaction_count']}")
            print(f"   Task Budgets: {ctx['active_task_budgets']}")
            print(f"\n5. Safety Classifier")
            print(f"   Enabled: {sf['enabled']}")
            print(f"   Rules: {sf['total_rules']}")
            print(f"   Refusals: {sf['refusal_count']}")
            print(f"\n6. Vision Agent")
            print(f"   Pillow: {'Available' if vi['pillow_available'] else 'Not available'}")
            print(f"   Tesseract: {'Available' if vi['tesseract_available'] else 'Not available'}")
            print()
            continue

        if line.lower() == "memory" or line.startswith("memory "):
            parts = line.split(" ", 2)
            sub = parts[1] if len(parts) > 1 else "status"
            if sub == "status":
                await cmd_memory_status(orchestrator)
            elif sub == "compact":
                await cmd_memory_compact(orchestrator)
            elif sub == "add" and len(parts) > 2:
                await cmd_memory_add(orchestrator, parts[2])
            else:
                print("Usage: memory [status|compact|add <content>]")
            continue

        if line.startswith("think "):
            result = await cmd_think(orchestrator, line[6:], "high")
            continue

        if line.startswith("python "):
            result = await cmd_sandbox_python(orchestrator, line[7:])
            continue

        if line.startswith("bash "):
            result = await cmd_sandbox_bash(orchestrator, line[5:])
            continue

        if line.startswith("safety "):
            result = await cmd_safety_check(orchestrator, line[7:])
            continue

        if line.startswith("vision "):
            result = await cmd_vision(orchestrator, line[7:])
            continue

        if line.lower() == "context":
            await cmd_context_status(orchestrator)
            continue

        if line.lower() in ("help", "?"):
            print("Commands: analyze, think, python, bash, memory, context, safety, vision, scan, agents, fable-status, help, quit")
            continue

        # ═══ Slash Command Handling (Claude Code port) ═══
        if line.startswith("/"):
            cmd_result = await orchestrator.command_registry.execute(line, orchestrator)
            if cmd_result:
                print(f"\n{cmd_result.output}\n")
                if cmd_result.data:
                    import json
                    print(f"  — {cmd_result.duration_ms:.0f}ms —")
            else:
                print(f"Unknown command: {line}")
            continue
        # ═══════════════════════════════════════════════════

        if line.startswith("analyze ") or line.startswith("scan "):
            parts = line.split(" ", 1)
            if len(parts) < 2:
                print("Usage: analyze <query>  OR  scan <path>")
                continue
            cmd = parts[0]
            arg = parts[1]
            print(f"\nProcessing...\n")
            if cmd == "analyze":
                result = await cmd_analyze(orchestrator, arg)
            else:
                await cmd_scan(orchestrator, arg)
        else:
            # Treat as an analyze query
            print(f"\nProcessing...\n")
            await cmd_analyze(orchestrator, line)


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel Cyber AI — Fable 5 Feature Parity Platform"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "analyze", "scan", "serve", "interactive", "benchmark",
            "plan", "evaluate", "scientific", "rag-index",
            "think", "sandbox", "memory", "context", "safety", "vision",
            "dashboard", "monitor", "webhook", "slack", "discord", "integrations",
            "siem", "auto-remediate",
            # Claude Code feature ports
            "mcp-server", "hook", "bridge",
        ],
        default="interactive",
        help="Command to run",
    )
    parser.add_argument(
        "args",
        nargs="*",
        help="Arguments for the command",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--effort", "-e",
        choices=["low", "medium", "high", "max"],
        default="high",
        help="Adaptive thinking effort level (Fable 5 feature)",
    )
    parser.add_argument(
        "--tags", "-t",
        default=None,
        help="Tags for memory add command (comma-separated)",
    )
    parser.add_argument(
        "--type",
        choices=["python", "bash"],
        default="python",
        help="Sandbox execution type",
    )

    args = parser.parse_args()

    # Initialize Sentry for CLI error tracking
    init_sentry()

    # Initialize the orchestrator
    orchestrator = setup_orchestrator()

    if args.command == "analyze":
        query = " ".join(args.args) if args.args else input("Enter security query: ")
        asyncio.run(cmd_analyze(orchestrator, query, args.format))

    elif args.command == "scan":
        path = args.args[0] if args.args else "."
        asyncio.run(cmd_scan(orchestrator, path))

    elif args.command == "think":
        query = " ".join(args.args) if args.args else input("Enter query to think about: ")
        asyncio.run(cmd_think(orchestrator, query, args.effort))

    elif args.command == "sandbox":
        code = " ".join(args.args) if args.args else input("Enter code/command: ")
        if args.type == "bash":
            asyncio.run(cmd_sandbox_bash(orchestrator, code))
        else:
            asyncio.run(cmd_sandbox_python(orchestrator, code))

    elif args.command == "memory":
        sub = args.args[0] if args.args else "status"
        if sub == "status":
            asyncio.run(cmd_memory_status(orchestrator))
        elif sub == "compact":
            asyncio.run(cmd_memory_compact(orchestrator))
        elif sub == "add":
            content = " ".join(args.args[1:]) if len(args.args) > 1 else input("Enter content: ")
            asyncio.run(cmd_memory_add(orchestrator, content, args.tags))
        else:
            print("Usage: memory [status|compact|add <content>]")

    elif args.command == "context":
        asyncio.run(cmd_context_status(orchestrator))

    elif args.command == "safety":
        content = " ".join(args.args) if args.args else input("Enter content to check: ")
        asyncio.run(cmd_safety_check(orchestrator, content))

    elif args.command == "vision":
        path = args.args[0] if args.args else input("Enter image path: ")
        asyncio.run(cmd_vision(orchestrator, path))

    elif args.command == "plan":
        goal = " ".join(args.args) if args.args else input("Enter goal: ")
        from src.planning.agentic_planner import AgenticPlanner
        import json
        planner = AgenticPlanner(orchestrator)
        result = asyncio.run(planner.run(goal))
        print(f"\nPlan Result: {len(result.get('findings', []))} findings")
        print(json.dumps(result, indent=2, default=str))

    elif args.command == "evaluate":
        from src.evaluation.swe_bench_evals import SentinelEvaluator
        from src.planning.agentic_planner import AgenticPlanner
        planner = AgenticPlanner(orchestrator)
        evaluator = SentinelEvaluator(orchestrator, planner)
        results = asyncio.run(evaluator.evaluate_all())
        evaluator.print_summary(results)

    elif args.command == "scientific":
        query = " ".join(args.args) if args.args else input("Enter scientific query: ")
        agent = orchestrator.get_agent("Scientific-Analyzer")
        if agent:
            result = asyncio.run(agent.analyze(query))
            print(result.to_markdown() if hasattr(result, 'to_markdown') else str(result))
        else:
            from src.science.scientific_agent import ScientificAnalysisAgent
            agent = ScientificAnalysisAgent()
            result = asyncio.run(agent.analyze(query))
            print(result.to_markdown() if hasattr(result, 'to_markdown') else str(result))

    elif args.command == "rag-index":
        path = args.args[0] if args.args else "."
        from src.rag.codebase_rag import CodebaseRAGAgent
        rag = CodebaseRAGAgent()
        result = rag.load_codebase(path)
        print(f"\n[RAG] Indexed {result.get('chunks', 0)} chunks from {path}")

    elif args.command == "dashboard":
        port = int(args.args[0]) if args.args else 8500
        print(f"\nStarting WebSocket Dashboard on http://localhost:{port}")
        from src.dashboard.dashboard_server import main
        main(port=port)

    elif args.command == "monitor":
        # Connect to orchestrator's monitoring system for real data
        mon = getattr(orchestrator, 'monitoring', None)
        if mon:
            status = mon.get_dashboard_data()
        else:
            from src.monitoring.monitor import MonitoringSystem
            mon = MonitoringSystem()
            status = mon.get_dashboard_data()

        print(f"\n{'='*60}")
        print(f"Sentinel Monitoring Status")
        print(f"{'='*60}")
        alerts_sec = status.get("alerts", {})
        stats = alerts_sec.get("stats", {})
        print(f"Alerts: {stats.get('total', 0)} total")
        print(f"  Critical: {stats.get('critical', 0)}")
        print(f"  Error:    {stats.get('error', 0)}")
        print(f"  Warning:  {stats.get('warning', 0)}")
        print(f"  Info:     {stats.get('info', 0)}")
        threats = status.get("active_threats", {})
        print(f"\nActive Threats: {threats.get('count', 0)}")
        metrics = status.get("metrics", {})
        for name, summary in metrics.items():
            if isinstance(summary, dict) and summary.get('count', 0) > 0:
                print(f"  {name}: avg={summary.get('avg', 0):.2f}, max={summary.get('max', 0):.2f}")
        print()

    elif args.command == "webhook":
        from src.integrations.github_webhook import GitHubWebhookHandler
        handler = GitHubWebhookHandler()
        handler.set_orchestrator(orchestrator)
        sub = args.args[0] if args.args else "status"
        if sub == "status":
            stats = handler.get_stats()
            print(f"\n{'='*60}")
            print(f"GitHub Webhook Status")
            print(f"{'='*60}")
            for key, value in stats.items():
                print(f"  {key}: {value}")
            print()
        elif sub == "token" and len(args.args) > 1:
            os.environ["GITHUB_TOKEN"] = args.args[1]
            print(f"GITHUB_TOKEN set")
        elif sub == "secret" and len(args.args) > 1:
            os.environ["GITHUB_WEBHOOK_SECRET"] = args.args[1]
            print(f"GITHUB_WEBHOOK_SECRET set")
        else:
            print("Usage: webhook [status|token <value>|secret <value>]")

    elif args.command == "slack":
        from src.integrations.slack_bot import SlackBot
        bot = SlackBot()
        bot.set_orchestrator(orchestrator)
        if args.args and args.args[0] == "manifest":
            manifest = bot.get_slack_manifest()
            import json
            print(json.dumps(manifest, indent=2))
        elif args.args and args.args[0] == "token" and len(args.args) > 1:
            os.environ["SLACK_BOT_TOKEN"] = args.args[1]
            print(f"SLACK_BOT_TOKEN set")
        elif args.args and args.args[0] == "webhook" and len(args.args) > 1:
            os.environ["SLACK_WEBHOOK_URL"] = args.args[1]
            print(f"SLACK_WEBHOOK_URL set")
        else:
            print("Usage: slack [manifest|token <value>|webhook <url>]")

    elif args.command == "discord":
        from src.integrations.discord_bot import DiscordBot
        bot = DiscordBot()
        bot.set_orchestrator(orchestrator)
        if args.args and args.args[0] == "commands":
            cmds = bot.get_discord_commands()
            import json
            print(json.dumps(cmds, indent=2))
        elif args.args and args.args[0] == "register" and len(args.args) > 2:
            import asyncio
            asyncio.run(bot.register_commands(args.args[1], args.args[2] if len(args.args) > 2 else None))
        else:
            print("Usage: discord [commands|register <token> <app_id>]")

    elif args.command == "siem":
        from src.integrations.siem import SIEMForwarder
        siem = SIEMForwarder()
        sub = args.args[0] if args.args else "status"
        if sub == "status":
            import json
            print(json.dumps(siem.get_stats(), indent=2))
        elif sub == "splunk" and len(args.args) > 2:
            siem.configure_splunk(args.args[1], args.args[2])
            print(f"Splunk HEC configured: {args.args[2]}")
        elif sub == "es" and len(args.args) > 1:
            siem.configure_elasticsearch(hosts=args.args[1:])
            print(f"Elasticsearch configured: {args.args[1]}")
        elif sub == "forward" and len(args.args) > 1:
            import asyncio, json
            filepath = args.args[1]
            try:
                with open(filepath) as f:
                    for line in f:
                        finding = json.loads(line)
                        asyncio.run(siem.forward_finding(finding))
                print(f"Forwarded findings from {filepath}")
            except Exception as e:
                print(f"Error forwarding from {filepath}: {e}")
        else:
            print("Usage: siem [status|splunk <token> <url>|es <host>|forward <file>]")

    elif args.command == "auto-remediate":
        from src.integrations.auto_remediation import AutoRemediationEngine, auto_remediate_finding
        engine = AutoRemediationEngine(orchestrator)
        engine._enabled = True
        sub = args.args[0] if args.args else "status"
        if sub == "status":
            stats = engine.get_stats()
            print(f"\n{'='*60}")
            print(f"Auto-Remediation Status")
            print(f"{'='*60}")
            for key, value in stats.items():
                if key != "recent_remediations" and key != "recent_prs":
                    print(f"  {key}: {value}")
            if stats["recent_remediations"]:
                print(f"\nRecent Remediations:")
                for r in stats["recent_remediations"]:
                    print(f"  {r['id']}: {r['file']} ({r['severity']}) - {r['status']}")
            if stats["recent_prs"]:
                print(f"\nRecent PRs:")
                for p in stats["recent_prs"]:
                    print(f"  {p['id']}: {p.get('url', 'N/A')} - {p['status']}")
        elif sub == "fix" and len(args.args) > 2:
            import asyncio, json
            finding = {
                "id": f"cli-{int(time.time())}",
                "title": args.args[2],
                "description": " ".join(args.args[3:]) if len(args.args) > 3 else "Auto-fix via CLI",
                "severity": "HIGH",
            }
            if len(args.args) > 3:
                file_path = args.args[1]
                source = " ".join(args.args[3:])
                result = asyncio.run(auto_remediate_finding(
                    orchestrator, finding, args.args[1], file_path, source
                ))
            else:
                print("Usage: auto-remediate fix <repo> <title> [description]")
        else:
            print("Usage: auto-remediate [status|fix <repo> <title> [description]]")

    elif args.command == "integrations":
        print(f"\n{'='*60}")
        print(f"Sentinel Integrations")
        print(f"{'='*60}")
        slack_cfg = 'configured' if os.environ.get('SLACK_BOT_TOKEN') else 'not configured'
        discord_cfg = 'configured' if os.environ.get('DISCORD_BOT_TOKEN') else 'not configured'
        gh_cfg = 'configured' if os.environ.get('GITHUB_WEBHOOK_SECRET') else 'not configured'
        print(f"\n1. Slack Bot ({slack_cfg})")
        print(f"   Commands: /sentinel-analyze, /sentinel-scan, /sentinel-status, /sentinel-help")
        print(f"   Setup: python -m src.main slack manifest")
        print(f"\n2. Discord Bot ({discord_cfg})")
        print(f"   Commands: /sentinel analyze, /sentinel scan, /sentinel status, /sentinel help")
        print(f"   Setup: python -m src.main discord commands")
        print(f"\n3. GitHub Webhook ({gh_cfg})")
        print(f"   Events: push, pull_request")
        print(f"   Setup: python -m src.main webhook status")
        print(f"\n4. Monitoring System (always active)")
        print(f"   Channels: console, Slack webhook, Discord webhook, generic webhook, PagerDuty")
        print(f"   Status: python -m src.main monitor")
        print(f"\n5. Production Docker Stack")
        print(f"   Services: PostgreSQL, Redis, Nginx, API, Dashboard, Worker")
        print(f"   Launch: docker compose -f docker/docker-compose.prod.yml up -d")
        print()

    elif args.command == "mcp-server":
        """Start the MCP server in standalone mode (JSON-RPC over stdio).

        Usage: python -m src.main mcp-server
        This starts the MCP server that reads JSON-RPC requests from stdin
        and writes responses to stdout, one JSON object per line.
        """
        async def _run_mcp_standalone():
            mcp = orchestrator.mcp_server
            logger.info("MCP Server starting in standalone mode (stdio)")
            print("Sentinel MCP Server ready", file=sys.stderr)
            await mcp.start()

        asyncio.run(_run_mcp_standalone())

    elif args.command == "hook":
        """Run git hooks with permission verification.

        Usage: python -m src.main hook pre-commit
               python -m src.main hook pre-push
               python -m src.main hook commit-msg <file>
        """
        hook_type = args.args[0] if args.args else "pre-commit"
        hook_args = args.args[1:] if len(args.args) > 1 else []

        from src.hooks.git_hooks import execute_hook
        result = asyncio.run(execute_hook(hook_type, hook_args, orchestrator))

        if result.success:
            print(f"✅ {hook_type}: {result.output}")
        else:
            print(f"❌ {hook_type}: {result.output}")
            for err in result.errors:
                print(f"   • {err}")
            sys.exit(1)

    elif args.command == "bridge":
        """Start the IDE Bridge server.

        Usage: python -m src.main bridge [port]
        Default port: 9876
        """
        port = int(args.args[0]) if args.args else 9876

        async def _run_bridge():
            from src.bridge.ide_bridge import IDEBridgeServer
            bridge = IDEBridgeServer(port=port)

            # Register editor commands that delegate to orchestrator
            async def _handle_review(cmd):
                result = await orchestrator.process(f"/review {cmd.args}")
                return result.get("summary", "")
            bridge.register_editor_command("review", _handle_review)

            async def _handle_analyze(cmd):
                result = await orchestrator.process(cmd.args)
                return result.get("summary", "")
            bridge.register_editor_command("analyze", _handle_analyze)

            await bridge.start()
            print(f"IDE Bridge running on ws://127.0.0.1:{port}")
            print("Press Ctrl+C to stop")

            # Keep running until interrupted
            try:
                while True:
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                await bridge.shutdown()

        asyncio.run(_run_bridge())

    elif args.command == "serve":
        from src.api.server import serve
        serve()

    elif args.command == "benchmark":
        from src.benchmark.ctf_benchmark import run_benchmark
        asyncio.run(run_benchmark(orchestrator))

    else:
        asyncio.run(cmd_interactive(orchestrator))


if __name__ == "__main__":
    main()
