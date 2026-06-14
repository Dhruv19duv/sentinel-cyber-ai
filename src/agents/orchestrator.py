"""Multi-Agent Orchestrator — The brain of Sentinel.

Coordinates specialized agents using LangGraph-style orchestration:
1. Route → classify the query intent
2. Dispatch → send to primary agent
3. Verify → check results, dispatch secondary agents if needed
4. Synthesize → combine findings into unified response
5. Report → generate final output

This is what makes Sentinel more powerful than Mythos — Mythos uses a single
agent, while we coordinate a team of specialized experts.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.router.model_router import route_query, classify_intent
from src.agents.base_agent import AgentResult, BaseAgent

# Fable 5 feature parity imports
from src.thinking.adaptive_thinking import AdaptiveThinkingEngine, ThinkingConfig, EffortLevel
from src.sandbox.code_executor import CodeExecutor, SandboxConfig
from src.memory.persistent_memory import PersistentMemory, MemoryConfig
from src.context.context_manager import ContextManager, ContextConfig
from src.safety.safety_classifier import SafetyClassifier, FallbackManager, SafetyResult
from src.vision.vision_agent import VisionAgent
from src.monitoring.monitor import MonitoringSystem, AlertSeverity, AlertChannel

# Claude Code feature ports
from src.commands.base import CommandRegistry
from src.permissions.permission_manager import PermissionManager
from src.mcp.mcp_server import MCPServer, MCPToolDefinition

logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinates multiple specialized agents for security analysis.

    Fable 5 Feature Parity — Now includes:
    - Adaptive Thinking Engine (configurable effort parameter)
    - Code Execution Sandbox (Docker-based with Python 3.11)
    - Persistent Memory System (tiered memory with compaction)
    - Context Manager (1M token context window)
    - Safety Classifier + Fallback (refusal system)
    - Vision Agent (multimodal analysis)
    """

    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}
        self._task_history: List[Dict[str, Any]] = []
        
        # Fable 5 feature parity subsystems
        self.thinking_engine = AdaptiveThinkingEngine()
        self.code_executor = CodeExecutor()
        self.memory = PersistentMemory()
        self.context_manager = ContextManager()
        self.safety_classifier = SafetyClassifier()
        self.fallback_manager = FallbackManager(self.safety_classifier)
        self.vision_agent = VisionAgent()
        
        # Monitoring & alerting system (beyond Fable 5)
        self.monitoring = MonitoringSystem()
        
        # ═══ Claude Code Feature Ports ═══
        # Slash Command System — Ported from Claude Code's src/commands/
        self.command_registry = CommandRegistry()
        
        # Fine-grained Permission System — Ported from Claude Code's src/hooks/toolPermission/
        self.permission_manager = PermissionManager()
        
        # MCP Server — Ported from Claude Code's MCP implementation
        self.mcp_server = MCPServer()
        # ═══════════════════════════════════
        
        logger.info(
            "Sentinel Orchestrator initialized with Fable 5 feature parity:\n"
            f"  - Thinking: {self.thinking_engine.get_effort().value} (default effort)\n"
            f"  - Sandbox: {'Docker' if self.code_executor._docker_available else 'Local'}\n"
            f"  - Memory: {self.memory.config.memory_dir}\n"
            f"  - Context: {self.context_manager.config.max_context_tokens:,} tokens\n"
            f"  - Safety: {len(self.safety_classifier._compiled_rules)} rules\n"
            f"  - Vision: Available\n"
            f"  - Monitoring: Active ({len(self.monitoring._webhook_urls)} webhooks)\n"
            f"  - Commands: {len(self.command_registry)} registered\n"
            f"  - Permissions: {len(self.permission_manager._rules)} rules\n"
            f"  - MCP Tools: {self.mcp_server.registry.tool_count} available"
        )

    def register_all_commands(self):
        """Register all built-in slash commands."""
        from src.commands.git_commands import GIT_COMMANDS
        from src.commands.review_commands import REVIEW_COMMANDS
        from src.commands.memory_commands import memory_command
        from src.commands.config_commands import CONFIG_COMMANDS
        from src.commands.diagnostic_commands import DIAGNOSTIC_COMMANDS
        from src.commands.help_commands import help_command
        
        # Register all command groups
        self.command_registry.register_all(GIT_COMMANDS)
        self.command_registry.register_all(REVIEW_COMMANDS)
        self.command_registry.register_all(CONFIG_COMMANDS)
        self.command_registry.register_all(DIAGNOSTIC_COMMANDS)
        self.command_registry.register(memory_command)
        self.command_registry.register(help_command)
        
        logger.info(
            f"Registered {len(self.command_registry)} slash commands: "
            f"{', '.join(cmd.name for cmd in self.command_registry.get_all(include_hidden=True))}"
        )
        
        # Wire up MCP tool handlers after commands are available
        self._register_mcp_handlers()

    def _register_mcp_handlers(self):
        """Register MCP tool handlers that delegate to the orchestrator.
        
        This wires up the 16 MCP tool definitions with actual handler
        functions that call orchestrator subsystems.
        """
        handlers = {}  # tool_name -> handler function
        
        async def handle_analyze_code(params):
            code = params.get("code", "")
            lang = params.get("language", "")
            result = await self.process(f"Analyze this {lang} code for vulnerabilities:\n```\n{code}\n```")
            return {"findings": result.get("findings", []), "summary": result.get("summary", "")}
        handlers["analyze_code"] = handle_analyze_code
        
        async def handle_execute_python(params):
            code = params.get("code", "")
            timeout = params.get("timeout", 30)
            result = await self.code_executor.execute_python(code, timeout=timeout)
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code, "files": result.files_created}
        handlers["execute_python"] = handle_execute_python
        
        async def handle_execute_bash(params):
            command = params.get("command", "")
            timeout = params.get("timeout", 30)
            result = await self.code_executor.execute_bash(command, timeout=timeout)
            return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code}
        handlers["execute_bash"] = handle_execute_bash
        
        async def handle_search_codebase(params):
            pattern = params.get("pattern", "")
            import subprocess, os
            try:
                result = subprocess.run(
                    ["grep" if os.name != "nt" else "findstr", "-rn", pattern],
                    capture_output=True, text=True, timeout=10
                )
                return {"results": result.stdout[:5000], "count": len(result.stdout.split(chr(10)))}
            except Exception as e:
                return {"error": str(e)}
        handlers["search_codebase"] = handle_search_codebase
        
        async def handle_read_file(params):
            path = params.get("path", "")
            max_length = params.get("max_length")
            try:
                with open(path, "r", errors="ignore") as f:
                    content = f.read(max_length) if max_length else f.read()
                return {"content": content, "path": path, "size": len(content)}
            except Exception as e:
                return {"error": str(e)}
        handlers["read_file"] = handle_read_file
        
        async def handle_write_file(params):
            path = params.get("path", "")
            content = params.get("content", "")
            import os
            try:
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w") as f:
                    f.write(content)
                return {"success": True, "path": path, "size": len(content)}
            except Exception as e:
                return {"error": str(e)}
        handlers["write_file"] = handle_write_file
        
        async def handle_list_directory(params):
            path = params.get("path", ".")
            recursive = params.get("recursive", False)
            try:
                import os
                if recursive:
                    items = []
                    for root, dirs, files in os.walk(path):
                        for d in dirs:
                            items.append(os.path.join(root, d) + "/")
                        for f in files:
                            items.append(os.path.join(root, f))
                else:
                    items = os.listdir(path)
                return {"path": path, "items": items, "count": len(items)}
            except Exception as e:
                return {"error": str(e)}
        handlers["list_directory"] = handle_list_directory
        
        async def handle_think(params):
            query = params.get("query", "")
            effort = params.get("effort", "high")
            self.thinking_engine.set_effort(effort)
            result = await self.thinking_engine.think(query)
            return {
                "response": result.final_response,
                "effort": result.effort_used.value,
                "tokens": result.total_thinking_tokens,
                "time_ms": result.thinking_time_ms,
            }
        handlers["think"] = handle_think
        
        async def handle_run_security_scan(params):
            target = params.get("target", "")
            scan_type = params.get("scan_type", "vulnerability")
            result = await self.process(f"Run a {scan_type} scan on:\n{target}")
            return {"findings": result.get("findings", []), "summary": result.get("summary", "")}
        handlers["run_security_scan"] = handle_run_security_scan
        
        async def handle_generate_patch(params):
            code = params.get("code", "")
            vulnerability = params.get("vulnerability", "")
            lang = params.get("language", "")
            result = await self.process(f"Generate a patch to fix {vulnerability} in this {lang} code:\n```\n{code}\n```")
            return {"patch": result.get("summary", ""), "findings": result.get("findings", [])}
        handlers["generate_patch"] = handle_generate_patch
        
        async def handle_query_memory(params):
            query = params.get("query", "")
            ctx = self.memory.get_compressed_context()
            return {"context": ctx[:2000], "status": self.memory.get_status()}
        handlers["query_memory"] = handle_query_memory
        
        async def handle_store_memory(params):
            content = params.get("content", "")
            tags = params.get("tags", [])
            self.memory.add_project_entry(content, tags=tags)
            return {"success": True, "content": content[:100]}
        handlers["store_memory"] = handle_store_memory
        
        async def handle_check_permissions(params):
            operation = params.get("operation", "")
            resource = params.get("resource", "")
            result = self.permission_manager.check(operation, resource)
            return {"allowed": result.allowed, "mode": result.mode.value, "reason": result.reason}
        handlers["check_permissions"] = handle_check_permissions
        
        async def handle_get_system_info(params):
            category = params.get("category", "all")
            info = {}
            if category in ("all", "system"):
                import os, platform, sys
                info["system"] = {"platform": platform.platform(), "python": sys.version, "cwd": os.getcwd()}
            if category in ("all", "agents"):
                info["agents"] = {"count": len(self._agents), "names": list(self._agents.keys())}
            if category in ("all", "memory"):
                info["memory"] = self.memory.get_status()
            if category in ("all", "tools"):
                info["tools"] = {"mcp_count": self.mcp_server.registry.tool_count, "tool_names": [t["name"] for t in self.mcp_server.registry.list_tools()]}
            if category in ("all", "commands"):
                info["commands"] = {"count": len(self.command_registry), "names": [c.name for c in self.command_registry.get_all()]}
            return info
        handlers["get_system_info"] = handle_get_system_info
        
        async def handle_run_command(params):
            cmd = params.get("command", "")
            args = params.get("args", "")
            full_input = f"{cmd} {args}" if args else cmd
            result = await self.process(full_input)
            return {"output": result.get("summary", ""), "success": result.get("status") != "error"}
        handlers["run_command"] = handle_run_command
        
        # Register all handlers with the MCP server
        for name, handler in handlers.items():
            definition = self.mcp_server.registry.get_tool(name)
            if definition:
                self.mcp_server.register_tool(definition, handler)
        
        logger.info(f"Registered {len(handlers)} MCP tool handlers")

    def register_agent(self, agent: BaseAgent) -> None:
        """Register a specialized agent with the orchestrator."""
        self._agents[agent.name] = agent
        logger.info(f"Registered agent: {agent.name} ({agent.model_name})")

    def get_agent(self, name: str) -> Optional[BaseAgent]:
        return self._agents.get(name)

    @property
    def registered_agents(self) -> List[str]:
        return list(self._agents.keys())

    async def process(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        parallel_agents: bool = True,
        check_permissions: bool = True,
    ) -> Dict[str, Any]:
        """Process a security query through the multi-agent pipeline.

        Args:
            query: The user's security query or code
            context: Optional context
            parallel_agents: If True, run secondary agents in parallel

        Returns:
            Complete analysis result with findings from all agents
        """
        task_id = f"task-{len(self._task_history) + 1}-{datetime.utcnow().timestamp()}"
        process_start = time.time()
        logger.info(f"[{task_id}] Processing query: {query[:100]}...")

        # Record metric: analysis started
        self.monitoring.record_metric("analysis_count", 1, {"task_id": task_id})

        # Step 0: Check if this is a slash command
        if query.startswith("/"):
            cmd_result = await self.command_registry.execute(query, self, context)
            if cmd_result:
                return {
                    "task_id": task_id,
                    "status": "success" if cmd_result.success else "error",
                    "summary": cmd_result.output[:200],
                    "findings": [],
                    "confidence": 1.0 if cmd_result.success else 0.0,
                    "agents_used": ["commands"],
                    "command_result": cmd_result.to_dict() if hasattr(cmd_result, 'to_dict') else {
                        "success": cmd_result.success,
                        "output": cmd_result.output[:500],
                    },
                }

        # Step 0.5: Permission check (Claude Code feature)
        if check_permissions:
            perm_result = self.permission_manager.check("request", "analyze")
            if not perm_result.allowed and not perm_result.requires_confirmation:
                return {
                    "task_id": task_id,
                    "status": "denied",
                    "summary": f"Request denied by permission system: {perm_result.reason}",
                    "findings": [],
                    "confidence": 0,
                    "agents_used": [],
                }

        # Step 0.5: Safety Classification (Fable 5 feature)
        safety_result = self.safety_classifier.classify_query(query)
        if not safety_result.is_safe:
            logger.warning(f"[{task_id}] Query refused by safety classifier: {safety_result.refusal_reason}")
            fallback_model = self.fallback_manager.get_fallback_model(
                "primary", safety_result.refusal_reason
            )
            refusal_response = {
                "task_id": task_id,
                "status": "refused",
                "stop_reason": "refusal",
                "refusal_reason": safety_result.refusal_reason.value,
                "summary": safety_result.suggested_action or "Request was refused by safety filters.",
                "findings": [{
                    "title": "Content Refused",
                    "description": safety_result.suggested_action or "This request was refused by safety classifiers.",
                    "severity": safety_result.severity.upper(),
                    "refusal_reason": safety_result.refusal_reason.value,
                    "fallback_available": safety_result.fallback_available,
                    "fallback_model": fallback_model,
                }],
                "confidence": 0,
                "safety_result": safety_result.to_dict(),
            }
            self._task_history.append({
                "task_id": task_id,
                "query": query,
                "status": "refused",
                "timestamp": datetime.utcnow().isoformat(),
            })
            return refusal_response

        # Step 0.75: Adaptive Thinking (Fable 5 feature)
        thinking_result = await self.thinking_engine.think(
            query, context, tool_steps=0
        )
        thinking_blocks = [b.to_dict() for b in thinking_result.thinking_blocks]

        # Step 1: Route the query
        routing = route_query(query, context)
        logger.info(f"[{task_id}] Routing: {routing['reasoning']}")

        # Step 2: Execute primary agent
        primary_agent = self._agents.get(routing["primary_agent"])
        if not primary_agent:
            return {
                "task_id": task_id,
                "status": "error",
                "error": f"Agent '{routing['primary_agent']}' not registered",
                "routing": routing,
            }

        logger.info(f"[{task_id}] Running primary agent: {primary_agent.name}")
        primary_result = await primary_agent.run(query, context)

        # Step 3: Execute secondary agents (in parallel if configured)
        secondary_results: List[AgentResult] = []
        if routing["secondary_agents"]:
            agents_to_run = []
            for agent_name in routing["secondary_agents"]:
                agent = self._agents.get(agent_name)
                if agent:
                    agents_to_run.append(agent.run(query, context))

            if parallel_agents and agents_to_run:
                logger.info(
                    f"[{task_id}] Running {len(agents_to_run)} secondary agents in parallel"
                )
                secondary_results = await asyncio.gather(*agents_to_run)
            else:
                for agent in [self._agents.get(n) for n in routing["secondary_agents"]]:
                    if agent:
                        secondary_results.append(await agent.run(query, context))

        # Step 4: Synthesize all results
        all_results = [primary_result] + secondary_results
        synthesized = self._synthesize_results(all_results, routing)

        process_duration = (time.time() - process_start) * 1000

        # Record metrics: latency, confidence, errors
        self.monitoring.record_metric("latency_ms", process_duration, {"task_id": task_id})
        self.monitoring.record_metric("confidence", synthesized["confidence"], {"task_id": task_id})
        self.monitoring.record_metric("detections", len(synthesized["findings"]), {"task_id": task_id})

        if synthesized["status"] == "error":
            self.monitoring.record_metric("errors", 1, {"task_id": task_id})

        # Send alert for critical findings
        critical_findings = [f for f in synthesized["findings"] if f.get("severity") == "CRITICAL"]
        if critical_findings:
            asyncio.create_task(
                self.monitoring.send_alert(
                    title=f"Critical findings in {task_id}",
                    message=f"Found {len(critical_findings)} critical issue(s): "
                            f"{', '.join(f.get('title', 'unknown') for f in critical_findings[:3])}",
                    severity=AlertSeverity.CRITICAL,
                    source="orchestrator",
                    channel=AlertChannel.CONSOLE,
                    metadata={"task_id": task_id, "findings": len(critical_findings)},
                )
            )

            # Track as active threats
            for finding in critical_findings[:5]:
                self.monitoring.track_threat(
                    description=finding.get("description", "Unknown vulnerability")[:200],
                    severity=AlertSeverity.CRITICAL,
                    source_agent=finding.get("agent", "scanner"),
                    affected_files=[finding.get("location", "unknown")],
                    confidence=finding.get("confidence", 0.8),
                )

        # Step 5: Record task
        task_record = {
            "task_id": task_id,
            "query": query,
            "routing": routing,
            "results": [r.to_dict() for r in all_results],
            "synthesis": synthesized,
            "duration_ms": process_duration,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._task_history.append(task_record)

        return {
            "task_id": task_id,
            "status": synthesized["status"],
            "summary": synthesized["summary"],
            "findings": synthesized["findings"],
            "confidence": synthesized["confidence"],
            "agents_used": [r.agent_name for r in all_results],
            "routing": routing,
            "agent_results": [r.to_dict() for r in all_results],
            # Fable 5 feature parity fields
            "thinking": {
                "effort": thinking_result.effort_used.value,
                "blocks": thinking_blocks,
                "tokens": thinking_result.total_thinking_tokens,
                "time_ms": thinking_result.thinking_time_ms,
                "interleaved_steps": thinking_result.interleaved_steps,
            },
            "context": {
                "tokens_used": self.context_manager.current_tokens,
                "tokens_available": self.context_manager.available_tokens,
                "usage_ratio": self.context_manager.usage_ratio,
            },
        }

    def _synthesize_results(
        self,
        results: List[AgentResult],
        routing: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Synthesize multiple agent results into a unified finding.

        This is where the ensemble effect happens — combining specialized
        perspectives for more accurate results than any single agent.
        """
        if not results:
            return {
                "status": "error",
                "summary": "No results to synthesize",
                "findings": [],
                "confidence": 0.0,
            }

        successful = [r for r in results if r.status == "success"]
        partial = [r for r in results if r.status == "partial"]
        errors = [r for r in results if r.status == "error"]

        # Aggregate findings, deduplicating by title
        all_findings: Dict[str, Dict[str, Any]] = {}
        for result in successful + partial:
            for finding in result.findings:
                key = finding.get("title", "unknown")
                if key not in all_findings:
                    all_findings[key] = finding
                else:
                    # Merge — keep higher severity
                    existing = all_findings[key]
                    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    if severity_order.get(finding.get("severity", "LOW"), 0) > severity_order.get(
                        existing.get("severity", "LOW"), 0
                    ):
                        all_findings[key] = finding

        # Calculate aggregate confidence
        confidences = [r.confidence for r in successful if r.confidence > 0]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

        # Determine overall status
        if len(successful) == len(results):
            status = "success"
        elif len(successful) + len(partial) >= len(results) / 2:
            status = "partial"
        else:
            status = "error"

        # Build summary
        total_findings = len(all_findings)
        critical = sum(1 for f in all_findings.values() if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings.values() if f.get("severity") == "HIGH")

        summary_parts = [
            f"Analyzed by {len(successful)} agent(s)",
            f"found {total_findings} issue(s)",
        ]
        if critical:
            summary_parts.append(f"{critical} critical")
        if high:
            summary_parts.append(f"{high} high severity")
        if errors:
            summary_parts.append(f"{len(errors)} agent(s) encountered errors")

        return {
            "status": status,
            "summary": " — ".join(summary_parts),
            "findings": list(all_findings.values()),
            "confidence": round(avg_confidence, 3),
            "agents_used": len(results),
            "agents_successful": len(successful),
            "agents_partial": len(partial),
            "agents_errors": len(errors),
        }

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent task history."""
        return self._task_history[-limit:]

    async def benchmark_agents(self, test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run benchmark test cases through all agents and score results."""
        results = {}
        for case in test_cases:
            query = case.get("query", "")
            expected = case.get("expected", {})
            result = await self.process(query)
            results[case.get("name", query[:50])] = {
                "expected": expected,
                "actual": result,
                "match": self._score_match(result, expected),
            }
        return results

    def _score_match(self, actual: Dict, expected: Dict) -> float:
        """Score how well the actual result matches expected."""
        score = 0.0
        if actual.get("status") == expected.get("status", "success"):
            score += 0.3
        if len(actual.get("findings", [])) >= len(expected.get("findings", [])):
            score += 0.3
        if actual.get("confidence", 0) >= expected.get("min_confidence", 0):
            score += 0.4
        return score
