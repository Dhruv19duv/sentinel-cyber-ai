"""API Routes — REST endpoints for the Sentinel multi-agent system.

Endpoints:
- POST /analyze — Analyze a security query
- POST /scan — Scan a codebase
- GET /agents — List registered agents
- GET /status — System health check
- POST /batch — Batch analysis
- POST /report — Generate report from analysis
- GET /history — Recent analysis history
- POST /benchmark — Run benchmarks
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, BackgroundTasks
from src.api.schemas import (
    AnalyzeRequest, AnalyzeResponse, ScanRequest,
    AgentInfo, SystemStatus, BatchAnalyzeRequest,
    BenchmarkResult, ReportRequest,
)
from src.agents.report_agent import ReportGeneratorAgent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["sentinel"])
_report_generator = ReportGeneratorAgent()


def setup_routes(orchestrator):
    """Configure routes with the orchestrator instance."""

    @router.post("/analyze", response_model=AnalyzeResponse)
    async def analyze(request: AnalyzeRequest):
        """Analyze a security query through the multi-agent system."""
        try:
            result = await orchestrator.process(
                query=request.query,
                context=request.context,
                parallel_agents=request.parallel_agents,
            )

            return AnalyzeResponse(
                task_id=result.get("task_id", "unknown"),
                status=result.get("status", "error"),
                summary=result.get("summary", ""),
                findings=result.get("findings", []),
                confidence=result.get("confidence", 0.0),
                agents_used=result.get("agents_used", []),
                routing=result.get("routing"),
                agent_results=result.get("agent_results"),
            )
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @router.post("/scan")
    async def scan_codebase(request: ScanRequest):
        """Scan a codebase for vulnerabilities."""
        import os
        import glob

        if not os.path.exists(request.path):
            raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")

        # Collect files
        extensions = ["*.py", "*.js", "*.ts", "*.java", "*.go", "*.rs", "*.cpp", "*.c"]
        files = []
        for ext in extensions:
            if request.language and ext != f"*.{request.language}":
                continue
            files.extend(glob.glob(os.path.join(request.path, "**", ext), recursive=True))

        # Apply exclude patterns
        if request.exclude_patterns:
            import re
            files = [
                f for f in files
                if not any(re.match(p, f) for p in request.exclude_patterns)
            ]

        # Limit files
        files = files[:request.max_files]

        # Analyze in batches
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

        return {
            "status": "complete",
            "files_scanned": len(files),
            "total_findings": len(all_findings),
            "critical": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
            "findings": all_findings,
        }

    @router.get("/agents", response_model=List[AgentInfo])
    async def list_agents():
        """List all registered agents with their capabilities."""
        return [
            AgentInfo(
                name=name,
                model=agent.model_name,
                tools=agent.tools,
                capabilities=list(orchestrator._agents.keys()),
            )
            for name, agent in orchestrator._agents.items()
        ]

    @router.get("/status", response_model=SystemStatus)
    async def get_status():
        """Get system health and status."""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        memory_mb = process.memory_info().rss / 1024 / 1024

        return SystemStatus(
            version="2.0.0",
            status="operational",
            registered_agents=list(orchestrator._agents.keys()),
            total_analyses=len(orchestrator._task_history),
            uptime_seconds=0.0,
            memory_usage_mb=memory_mb,
            active_tasks=0,
        )

    @router.post("/batch")
    async def batch_analyze(request: BatchAnalyzeRequest):
        """Analyze multiple queries in batch."""
        if request.parallel:
            tasks = [orchestrator.process(q) for q in request.queries]
            results = await asyncio.gather(*tasks)
        else:
            results = [await orchestrator.process(q) for q in request.queries]

        return {
            "total": len(results),
            "successful": sum(1 for r in results if r.get("status") == "success"),
            "results": [{
                "task_id": r.get("task_id"),
                "status": r.get("status"),
                "summary": r.get("summary"),
                "confidence": r.get("confidence"),
            } for r in results],
        }

    @router.post("/report")
    async def generate_report(request: ReportRequest):
        """Generate a report from a previous analysis."""
        # Find the task from history
        history = orchestrator.get_history()
        task = None
        for h in history:
            if h.get("task_id") == request.task_id:
                task = h
                break

        if not task:
            raise HTTPException(status_code=404, detail=f"Task not found: {request.task_id}")

        # Check if it's a direct result or history entry
        if "synthesis" in task:
            result = task
            result["findings"] = task.get("synthesis", {}).get("findings", [])
        else:
            result = task

        report = _report_generator.generate_report(
            result, report_type=request.report_type
        )
        return {
            "task_id": request.task_id,
            "report_type": request.report_type,
            "report": report,
        }

    @router.get("/history")
    async def get_history(limit: int = 10):
        """Get recent analysis history."""
        return orchestrator.get_history(limit=limit)

    @router.post("/benchmark")
    async def run_benchmark():
        """Run the benchmark suite against all agents."""
        from src.benchmark.ctf_benchmark import BenchmarkSuite
        suite = BenchmarkSuite(orchestrator)
        results = await suite.run_all()
        return results

    return router
