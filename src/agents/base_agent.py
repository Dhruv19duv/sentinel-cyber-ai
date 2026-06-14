"""Base Agent — Abstract foundation for all Sentinel agents.

Every agent in the system extends this class, providing:
- Common lifecycle (init → analyze → verify → report)
- Tool access management
- Model inference interface
- Result formatting
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import logging
import json
import time
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Standard result format for all agent operations."""
    agent_name: str
    status: str  # "success", "partial", "error", "timeout"
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    duration_ms: float = 0.0
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
            "findings": self.findings,
            "confidence": self.confidence,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "timestamp": self.timestamp,
        }

    def to_markdown(self) -> str:
        lines = [
            f"### 🤖 Agent: {self.agent_name}",
            f"**Status:** {self.status.upper()}",
            f"**Confidence:** {self.confidence:.1%}",
            f"**Duration:** {self.duration_ms:.0f}ms",
            "",
            f"**Summary:** {self.summary}",
        ]
        if self.findings:
            lines.append("")
            lines.append("**Findings:**")
            for f in self.findings[:10]:
                severity = f.get("severity", "INFO")
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                lines.append(f"- {icon} **{f.get('title', 'Issue')}** ({severity})")
                lines.append(f"  {f.get('description', '')[:200]}")
        if self.error:
            lines.append("")
            lines.append(f"**Error:** {self.error}")
        return "\n".join(lines)


class BaseAgent(ABC):
    """Abstract base class for all Sentinel agents."""

    def __init__(
        self,
        name: str,
        model_name: str,
        tools: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.model_name = model_name
        self.tools = tools or []
        self.config = config or {}
        self._model = None
        self._tokenizer = None

    @abstractmethod
    async def analyze(self, query: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Analyze a security query and return findings."""
        ...

    async def verify(self, result: AgentResult) -> AgentResult:
        """Verify the findings — override for agent-specific verification."""
        return result

    async def run(self, query: str, context: Optional[Dict[str, Any]] = None) -> AgentResult:
        """Full lifecycle: analyze → verify → return."""
        start = time.time()
        try:
            result = await self.analyze(query, context)
            result = await self.verify(result)
            result.duration_ms = (time.time() - start) * 1000
            return result
        except Exception as e:
            logger.error(f"Agent {self.name} failed: {e}")
            return AgentResult(
                agent_name=self.name,
                status="error",
                summary=f"Agent execution failed: {str(e)}",
                error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )

    def format_finding(
        self,
        title: str,
        description: str,
        severity: str = "MEDIUM",
        location: Optional[str] = None,
        remediation: Optional[str] = None,
        cwe: Optional[str] = None,
        **extra,
    ) -> Dict[str, Any]:
        """Create a standardized finding entry."""
        return {
            "title": title,
            "description": description,
            "severity": severity.upper(),
            "location": location,
            "remediation": remediation,
            "cwe": cwe,
            **extra,
        }
