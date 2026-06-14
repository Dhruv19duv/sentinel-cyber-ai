"""API Schemas — Pydantic models for the Sentinel API.

Defines request/response structures for:
- Security analysis requests
- Scan results
- Agent configurations
- Report formatting
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Request to analyze code or a security query."""
    query: str = Field(..., description="Security query or code to analyze")
    context: Optional[Dict[str, Any]] = Field(None, description="Optional context")
    scan_mode: str = Field(
        "auto",
        description="Analysis mode: auto, quick, deep, exploit, patch"
    )
    parallel_agents: bool = Field(True, description="Run agents in parallel")
    format: str = Field("text", description="Output format: text, json, report")


class ScanRequest(BaseModel):
    """Request to scan a codebase or repository."""
    path: str = Field(..., description="Path to codebase or repository URL")
    language: Optional[str] = Field(None, description="Language filter")
    exclude_patterns: Optional[List[str]] = Field(None, description="Exclude patterns")
    max_files: int = Field(100, description="Maximum files to scan")
    agent_config: Optional[Dict[str, Any]] = Field(None, description="Agent configuration")


class AnalyzeResponse(BaseModel):
    """Response from a security analysis."""
    task_id: str
    status: str
    summary: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0
    agents_used: List[str] = Field(default_factory=list)
    routing: Optional[Dict[str, Any]] = None
    agent_results: Optional[List[Dict[str, Any]]] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None


class AgentInfo(BaseModel):
    """Information about a registered agent."""
    name: str
    model: str
    tools: List[str]
    capabilities: List[str]


class SystemStatus(BaseModel):
    """System health and status."""
    version: str
    status: str
    registered_agents: List[str]
    total_analyses: int = 0
    uptime_seconds: float = 0.0
    memory_usage_mb: Optional[float] = None
    active_tasks: int = 0


class BatchAnalyzeRequest(BaseModel):
    """Batch analysis request."""
    queries: List[str] = Field(..., description="List of queries to analyze")
    parallel: bool = Field(True, description="Run queries in parallel")


class BenchmarkResult(BaseModel):
    """Results from a benchmark run."""
    benchmark_id: str
    total_tests: int
    passed: int
    failed: int
    success_rate: float
    average_confidence: float
    agent_performance: Dict[str, Dict[str, float]]
    details: List[Dict[str, Any]] = Field(default_factory=list)


class ReportRequest(BaseModel):
    """Request to generate a formatted report."""
    task_id: str
    report_type: str = Field("technical", description="Report format")
    include_details: bool = Field(True, description="Include detailed findings")
    format: str = Field("markdown", description="Output format")
