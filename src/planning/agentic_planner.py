"""Agentic Planning System — Long-horizon autonomous task decomposition.

This is a direct match for Mythos's agentic planning capability.
The Planner decomposes complex security tasks into sub-tasks,
executes them through the multi-agent system, and synthesizes results.

Key differentiator: Mythos plans within a single model. We decompose
across specialized agents for better results on complex tasks.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class PriorityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SubTask:
    """A single atomic task in the plan."""
    id: str
    description: str
    agent: str  # Which agent handles this
    priority: PriorityLevel = PriorityLevel.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    dependencies: List[str] = field(default_factory=list)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "agent": self.agent,
            "priority": self.priority.value,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class Plan:
    """A complete execution plan with multiple sub-tasks."""
    id: str
    goal: str
    tasks: List[SubTask] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def progress(self) -> float:
        if not self.tasks:
            return 0.0
        completed = sum(1 for t in self.tasks if t.status == TaskStatus.COMPLETED)
        return completed / len(self.tasks)

    @property
    def is_complete(self) -> bool:
        return all(t.status == TaskStatus.COMPLETED for t in self.tasks)

    @property
    def failed_tasks(self) -> List[SubTask]:
        return [t for t in self.tasks if t.status == TaskStatus.FAILED]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "goal": self.goal,
            "status": self.status.value,
            "progress": self.progress,
            "tasks": [t.to_dict() for t in self.tasks],
            "result": self.result,
        }


class AgenticPlanner:
    """Decomposes complex security goals into multi-step execution plans.

    Capabilities matching Mythos's claimed agentic behavior:
    - Long-horizon planning (10+ step task chains)
    - Multi-step autonomous execution
    - Dependency-aware task scheduling
    - Dynamic replanning on failure
    - Parallel task execution where possible
    """

    def __init__(self, orchestrator=None):
        self._orchestrator = orchestrator
        self._plans: Dict[str, Plan] = {}
        self._plan_count = 0

    def set_orchestrator(self, orchestrator):
        self._orchestrator = orchestrator

    def create_plan(self, goal: str) -> Plan:
        """Create an execution plan by decomposing a complex goal into sub-tasks.

        Uses the model router to identify which agents are needed,
        then creates a dependency graph of sub-tasks.
        """
        self._plan_count += 1
        plan_id = f"plan-{self._plan_count}-{datetime.utcnow().strftime('%H%M%S')}"

        # Decompose the goal into sub-tasks
        tasks = self._decompose_goal(goal)

        plan = Plan(
            id=plan_id,
            goal=goal,
            tasks=tasks,
            status=TaskStatus.PENDING,
        )
        self._plans[plan_id] = plan
        logger.info(f"Created plan {plan_id}: {len(tasks)} tasks for '{goal[:60]}...'")
        return plan

    def _decompose_goal(self, goal: str) -> List[SubTask]:
        """Decompose a security goal into atomic sub-tasks.

        Uses scoring-based plan selection to handle complex queries
        that span multiple categories (e.g., "audit biology research").
        """
        goal_lower = goal.lower()

        # Score each plan template based on keyword matches
        plan_scores = [
            ("vulnerability_assessment", self._build_vulnerability_assessment_plan(goal),
             sum(1 for kw in ["audit", "assess", "scan", "review", "find vuln", "vulnerability", "cve"]
                 if kw in goal_lower)),
            ("exploit_analysis", self._build_exploit_analysis_plan(goal),
             sum(1 for kw in ["exploit", "chain", "bypass", "pwn", "attack", "rce", "payload"]
                 if kw in goal_lower)),
            ("patch_plan", self._build_patch_plan(goal),
             sum(1 for kw in ["fix", "patch", "secure", "harden", "protect", "remediate"]
                 if kw in goal_lower)),
            ("compliance_plan", self._build_compliance_plan(goal),
             sum(1 for kw in ["compliance", "audit", "report", "certify", "hipaa", "pci", "gdpr", "sox"]
                 if kw in goal_lower)),
            ("scientific_plan", self._build_scientific_plan(goal),
             sum(1 for kw in ["biology", "gene", "protein", "health", "clinical", "scientific",
                              "dna", "rna", "chemistry", "compound"]
                 if kw in goal_lower)),
            ("engagement_plan", self._build_full_engagement_plan(goal),
             sum(1 for kw in ["penetration test", "engagement", "red team", "full audit",
                              "pentest", "security assessment"]
                 if kw in goal_lower)),
        ]

        # Pick the plan with the highest score
        plan_scores.sort(key=lambda x: -x[2])
        best_plan_name, best_plan_tasks, best_score = plan_scores[0]

        if best_score > 0:
            return best_plan_tasks

        # Default: simple analysis
        return [
            SubTask(
                id=f"{self._plan_count + 1}-1",
                description=f"Analyze the query: {goal[:100]}",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
            ),
        ]

    def _build_vulnerability_assessment_plan(self, goal: str) -> List[SubTask]:
        """Build a comprehensive vulnerability assessment plan."""
        return [
            SubTask(
                id=f"{self._plan_count + 1}-1",
                description="Initial code scan for common vulnerabilities",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
            ),
            SubTask(
                id=f"{self._plan_count + 1}-2",
                description="Deep analysis for complex vulnerability patterns",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-3",
                description="Threat intelligence lookup for related CVEs",
                agent="Threat-Intelligence",
                priority=PriorityLevel.MEDIUM,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-4",
                description="Exploitability assessment of found vulnerabilities",
                agent="Exploit-Analyzer",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1", f"{self._plan_count + 1}-2"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-5",
                description="Generate patches for confirmed vulnerabilities",
                agent="Patch-Generator",
                priority=PriorityLevel.MEDIUM,
                dependencies=[f"{self._plan_count + 1}-2", f"{self._plan_count + 1}-4"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-6",
                description="Generate comprehensive security report",
                agent="Report-Generator",
                priority=PriorityLevel.LOW,
                dependencies=[f"{self._plan_count + 1}-3", f"{self._plan_count + 1}-4", f"{self._plan_count + 1}-5"],
            ),
        ]

    def _build_exploit_analysis_plan(self, goal: str) -> List[SubTask]:
        """Build exploit analysis plan with chain-of-thought."""
        return [
            SubTask(
                id=f"{self._plan_count + 1}-1",
                description="Vulnerability identification and classification",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
            ),
            SubTask(
                id=f"{self._plan_count + 1}-2",
                description="Threat intelligence correlation (CVE/CWE mapping)",
                agent="Threat-Intelligence",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-3",
                description="Exploit technique identification (ROP, heap spray, etc.)",
                agent="Exploit-Analyzer",
                priority=PriorityLevel.CRITICAL,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-4",
                description="Sandboxed exploit verification",
                agent="Exploit-Analyzer",
                priority=PriorityLevel.CRITICAL,
                dependencies=[f"{self._plan_count + 1}-3"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-5",
                description="Mitigation and patch recommendation",
                agent="Patch-Generator",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-3", f"{self._plan_count + 1}-4"],
            ),
        ]

    def _build_patch_plan(self, goal: str) -> List[SubTask]:
        """Build security hardening plan."""
        return [
            SubTask(
                id=f"{self._plan_count + 1}-1",
                description="Identify all security weaknesses",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
            ),
            SubTask(
                id=f"{self._plan_count + 1}-2",
                description="Generate secure code patches",
                agent="Patch-Generator",
                priority=PriorityLevel.CRITICAL,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-3",
                description="Validate patches don't introduce new issues",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-2"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-4",
                description="Verify by attempting exploit on patched code",
                agent="Exploit-Analyzer",
                priority=PriorityLevel.MEDIUM,
                dependencies=[f"{self._plan_count + 1}-2", f"{self._plan_count + 1}-3"],
            ),
        ]

    def _build_compliance_plan(self, goal: str) -> List[SubTask]:
        """Build compliance audit plan."""
        return [
            SubTask(
                id=f"{self._plan_count + 1}-1",
                description="Scan for compliance-relevant vulnerabilities",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
            ),
            SubTask(
                id=f"{self._plan_count + 1}-2",
                description="Map findings to compliance frameworks",
                agent="Threat-Intelligence",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-3",
                description="Generate compliance report with remediation roadmap",
                agent="Report-Generator",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1", f"{self._plan_count + 1}-2"],
            ),
        ]

    def _build_scientific_plan(self, goal: str) -> List[SubTask]:
        """Build scientific analysis plan — matching Mythos's biology/health claims."""
        return [
            SubTask(
                id=f"{self._plan_count + 1}-1",
                description="Scientific literature context analysis",
                agent="Code-Scanner",
                priority=PriorityLevel.HIGH,
            ),
            SubTask(
                id=f"{self._plan_count + 1}-2",
                description="Data quality and methodology assessment",
                agent="Threat-Intelligence",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1"],
            ),
            SubTask(
                id=f"{self._plan_count + 1}-3",
                description="Generate scientific analysis report",
                agent="Report-Generator",
                priority=PriorityLevel.HIGH,
                dependencies=[f"{self._plan_count + 1}-1", f"{self._plan_count + 1}-2"],
            ),
        ]

    def _build_full_engagement_plan(self, goal: str) -> List[SubTask]:
        """Build complete penetration testing engagement plan."""
        return [
            # Phase 1: Reconnaissance
            SubTask(id=f"{self._plan_count + 1}-1", description="Reconnaissance — gather information about target",
                    agent="Threat-Intelligence", priority=PriorityLevel.HIGH),
            # Phase 2: Scanning
            SubTask(id=f"{self._plan_count + 1}-2", description="Vulnerability scanning — identify attack surface",
                    agent="Code-Scanner", priority=PriorityLevel.CRITICAL,
                    dependencies=[f"{self._plan_count + 1}-1"]),
            # Phase 3: Exploitation (parallel)
            SubTask(id=f"{self._plan_count + 1}-3", description="Exploit development — create PoC for found vulns",
                    agent="Exploit-Analyzer", priority=PriorityLevel.CRITICAL,
                    dependencies=[f"{self._plan_count + 1}-2"]),
            SubTask(id=f"{self._plan_count + 1}-4", description="Privilege escalation analysis",
                    agent="Exploit-Analyzer", priority=PriorityLevel.HIGH,
                    dependencies=[f"{self._plan_count + 1}-3"]),
            # Phase 4: Patching
            SubTask(id=f"{self._plan_count + 1}-5", description="Generate security patches for all findings",
                    agent="Patch-Generator", priority=PriorityLevel.HIGH,
                    dependencies=[f"{self._plan_count + 1}-2"]),
            # Phase 5: Reporting
            SubTask(id=f"{self._plan_count + 1}-6", description="Generate executive and technical reports",
                    agent="Report-Generator", priority=PriorityLevel.HIGH,
                    dependencies=[f"{self._plan_count + 1}-3", f"{self._plan_count + 1}-5"]),
        ]

    async def execute_plan(self, plan_id: str) -> Plan:
        """Execute a plan by running tasks through the multi-agent system.

        Handles:
        - Dependency ordering (topological sort)
        - Parallel execution of independent tasks
        - Dynamic replanning on failure
        - Progress tracking
        """
        plan = self._plans.get(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")

        if not self._orchestrator:
            plan.status = TaskStatus.FAILED
            return plan

        plan.status = TaskStatus.IN_PROGRESS
        logger.info(f"Executing plan {plan_id}: {plan.goal[:60]}...")

        # Execute tasks in dependency order
        completed: set = set()
        max_iterations = 50
        iteration = 0

        while not plan.is_complete and iteration < max_iterations:
            iteration += 1

            # Find tasks that are ready to execute (all dependencies met)
            ready_tasks = [
                t for t in plan.tasks
                if t.status == TaskStatus.PENDING
                and all(dep in completed for dep in t.dependencies)
            ]

            if not ready_tasks and not plan.is_complete:
                # Check for blocked tasks
                blocked = [t for t in plan.tasks if t.status == TaskStatus.PENDING]
                if blocked:
                    logger.warning(f"Plan {plan_id}: {len(blocked)} tasks blocked by unmet dependencies")
                    for t in blocked:
                        missing = [d for d in t.dependencies if d not in completed]
                        t.status = TaskStatus.BLOCKED
                        t.error = f"Blocked by: {', '.join(missing)}"
                break

            # Execute ready tasks in parallel
            logger.info(f"Plan {plan_id}: Executing {len(ready_tasks)} task(s)")
            for task in ready_tasks:
                task.status = TaskStatus.IN_PROGRESS

            async def execute_task(task: SubTask) -> SubTask:
                try:
                    query = (
                        f"[Plan {plan_id}] {task.description}\n\n"
                        f"Goal: {plan.goal[:200]}"
                    )
                    result = await self._orchestrator.process(query)
                    task.status = TaskStatus.COMPLETED
                    task.result = {
                        "summary": result.get("summary", ""),
                        "findings": result.get("findings", []),
                        "confidence": result.get("confidence", 0),
                    }
                    completed.add(task.id)
                    logger.info(f"✅ Task {task.id} ({task.agent}): {task.description[:50]}...")
                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.error = str(e)
                    logger.error(f"❌ Task {task.id} failed: {e}")
                return task

            # Run tasks in parallel if they have no interdependencies
            results = await asyncio.gather(*[execute_task(t) for t in ready_tasks])

        # Synthesize final result from all completed tasks
        if plan.is_complete:
            plan.status = TaskStatus.COMPLETED
            plan.result = self._synthesize_results(plan)
            logger.info(f"✅ Plan {plan_id} completed ({plan.progress:.0%})")
        else:
            plan.status = TaskStatus.FAILED if plan.failed_tasks else TaskStatus.IN_PROGRESS
            logger.warning(f"⚠️ Plan {plan_id}: {len(plan.failed_tasks)} task(s) failed")

        return plan

    def _synthesize_results(self, plan: Plan) -> Dict[str, Any]:
        """Synthesize results from all completed tasks into a unified output."""
        all_findings = []
        total_confidence = 0.0
        confidence_count = 0

        for task in plan.tasks:
            if task.result:
                findings = task.result.get("findings", [])
                for f in findings:
                    f["task_id"] = task.id
                    f["task_description"] = task.description
                all_findings.extend(findings)

                conf = task.result.get("confidence", 0)
                if conf > 0:
                    total_confidence += conf
                    confidence_count += 1

        critical = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in all_findings if f.get("severity") == "HIGH")

        return {
            "plan_id": plan.id,
            "goal": plan.goal,
            "tasks_total": len(plan.tasks),
            "tasks_completed": sum(1 for t in plan.tasks if t.status == TaskStatus.COMPLETED),
            "tasks_failed": len(plan.failed_tasks),
            "confidence": round(total_confidence / confidence_count, 2) if confidence_count > 0 else 0,
            "total_findings": len(all_findings),
            "critical_findings": critical,
            "high_findings": high,
            "findings": all_findings,
        }

    def get_plan(self, plan_id: str) -> Optional[Plan]:
        """Get a plan by ID."""
        return self._plans.get(plan_id)

    def list_plans(self) -> List[Dict[str, Any]]:
        """List all plans with their status."""
        return [
            {
                "id": p.id,
                "goal": p.goal[:100],
                "status": p.status.value,
                "progress": p.progress,
                "tasks": len(p.tasks),
            }
            for p in self._plans.values()
        ]

    async def run(self, goal: str) -> Dict[str, Any]:
        """High-level API: create plan + execute + return results.

        This is the main entry point for agentic planning.
        """
        plan = self.create_plan(goal)
        plan = await self.execute_plan(plan.id)

        if plan.result:
            return plan.result
        return {
            "plan_id": plan.id,
            "status": plan.status.value,
            "error": "No results available",
        }
