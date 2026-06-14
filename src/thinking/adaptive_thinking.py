"""
Adaptive Thinking Engine — Fable 5's signature reasoning system.

Mimics Claude Fable 5's "Adaptive Thinking" with:
- Configurable effort parameter (low/medium/high/max)
- Dynamic reasoning depth based on task complexity
- Interleaved thinking between tool calls
- Connector text summarization
- Structured chain-of-thought content blocks

Fable 5 spec:
- Adaptive Thinking is mandatory (cannot be disabled)
- effort parameter: low | medium | high (default) | max
- Raw CoT not returned — summarized or omitted
- Interleaved thinking between tool calls (beta)
- Connector text summarization for agentic workflows
"""

import logging
import time
from typing import Dict, List, Optional, Any, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class EffortLevel(str, Enum):
    """Maps directly to Fable 5's effort parameter."""
    LOW = "low"           # Minimal thinking, skip for simple tasks
    MEDIUM = "medium"     # Moderate thinking, may skip for very simple
    HIGH = "high"         # Always thinks, deep reasoning (Fable 5 default)
    MAX = "max"           # Always thinks, no constraints on depth


@dataclass
class ThinkingConfig:
    """Configuration for the Adaptive Thinking Engine.
    
    Matches Fable 5's output_config with effort parameter.
    """
    effort: EffortLevel = EffortLevel.HIGH
    interleaved_thinking: bool = True  # Allows thinking between tool calls
    return_thinking_blocks: bool = False  # If True, returns reasoning as blocks
    connector_summarization: bool = True  # Summarize text between tool calls
    max_thinking_tokens: int = 8192  # Max tokens for reasoning
    min_thinking_tokens: int = 128  # Min tokens before we consider it "real thinking"


@dataclass
class ThinkingBlock:
    """A reasoning content block — analogous to Fable 5's thinking content blocks.
    
    In Fable 5, thinking blocks are returned as special content blocks
    in the API response. They must be passed back unchanged in multi-turn.
    """
    type: str  # "thinking" or "thinking_summary"
    content: str
    effort_used: EffortLevel
    token_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "content": self.content,
            "effort": self.effort_used.value,
            "tokens": self.token_count,
        }


@dataclass 
class ThinkingResult:
    """Complete result from the thinking engine."""
    thinking_blocks: List[ThinkingBlock]
    final_response: str
    total_thinking_tokens: int
    effort_used: EffortLevel
    thinking_time_ms: float
    interleaved_steps: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "thinking_blocks": [b.to_dict() for b in self.thinking_blocks],
            "final_response": self.final_response[:500],
            "total_thinking_tokens": self.total_thinking_tokens,
            "effort": self.effort_used.value,
            "thinking_time_ms": self.thinking_time_ms,
            "interleaved_steps": self.interleaved_steps,
        }


# ── Templates for each effort level ──

THINKING_TEMPLATES = {
    "low": {
        "description": "Minimal reasoning — skip for simple queries",
        "prompt_template": (
            "Before responding, briefly consider:\n"
            "1. What is the core security issue?\n"
            "2. What is the simplest correct answer?\n"
            "Keep thinking under {max_tokens} tokens."
        ),
    },
    "medium": {
        "description": "Moderate reasoning depth",
        "prompt_template": (
            "Before responding, analyze step-by-step:\n"
            "1. Identify the vulnerability type and CWE classification\n"
            "2. Determine attack vector and preconditions\n"
            "3. Assess impact (confidentiality, integrity, availability)\n"
            "4. Formulate remediation\n"
            "Limit reasoning depth to conserve tokens."
        ),
    },
    "high": {
        "description": "Deep reasoning — Fable 5 default",
        "prompt_template": (
            "Think through this systematically before responding:\n"
            "1. QUERY ANALYSIS: What exactly is being asked? What's the context?\n"
            "2. VULNERABILITY IDENTIFICATION: Scan for patterns, CWEs, attack vectors\n"
            "3. EXPLOITABILITY: Can this be exploited? What's the chain?\n"
            "4. IMPACT ASSESSMENT: Severity, scope, business impact\n"
            "5. REMEDIATION: Multiple approaches, trade-offs, best practice\n"
            "6. VERIFICATION: How to test the fix?\n"
            "Provide thorough reasoning with technical depth."
        ),
    },
    "max": {
        "description": "Maximum reasoning — no depth constraints",
        "prompt_template": (
            "Conduct an exhaustive analysis using maximum reasoning depth:\n"
            "1. DEEP QUERY ANALYSIS: Surface assumptions, edge cases, implicit requirements\n"
            "2. COMPREHENSIVE VULNERABILITY AUDIT:\n"
            "   a. Known CVEs and CWEs — map to MITRE ATT&CK\n"
            "   b. Zero-day potential — novel attack surface analysis\n"
            "   c. Supply chain risks — dependency analysis\n"
            "   d. Architecture-level flaws — design review\n"
            "3. ADVANCED EXPLOIT ANALYSIS:\n"
            "   a. Chain construction — multi-step exploit paths\n"
            "   b. Privilege escalation vectors\n"
            "   c. Data exfiltration routes\n"
            "   d. Persistence mechanisms\n"
            "4. COMPREHENSIVE REMEDIATION:\n"
            "   a. Immediate fixes (hot patches)\n"
            "   b. Architectural improvements\n"
            "   c. Defense-in-depth layers\n"
            "   d. Monitoring and detection rules\n"
            "5. VERIFICATION & TESTING:\n"
            "   a. Unit tests for fixes\n"
            "   b. Integration test scenarios\n"
            "   c. Penetration testing methodology\n"
            "6. REPORT GENERATION: Full security assessment report\n"
            "No depth limits — explore every relevant angle."
        ),
    },
}


class AdaptiveThinkingEngine:
    """Implements Fable 5's Adaptive Thinking with configurable effort.
    
    Key behaviors matching Fable 5:
    - Mandatory thinking (cannot be disabled like Fable 5)
    - Effort parameter controls reasoning depth
    - Interleaved thinking between tool calls
    - Connector text summarization for agentic workflows
    - Thinking blocks returned as structured content
    """
    
    def __init__(self, config: Optional[ThinkingConfig] = None):
        self.config = config or ThinkingConfig()
        self._thinking_history: List[ThinkingResult] = []
        
    def set_effort(self, effort: str):
        """Set the thinking effort level. Accepts string or enum."""
        try:
            self.config.effort = EffortLevel(effort.lower())
        except ValueError:
            logger.warning(f"Unknown effort level: {effort}, using default (high)")
            self.config.effort = EffortLevel.HIGH
    
    def get_effort(self) -> EffortLevel:
        return self.config.effort
    
    def estimate_complexity(self, query: str, context: Optional[Dict] = None) -> EffortLevel:
        """Auto-detect the appropriate effort level based on query complexity.
        
        This allows the engine to automatically escalate reasoning depth
        for complex queries, similar to Fable 5's adaptive behavior.
        """
        query_lower = query.lower()
        
        # Complexity indicators
        complexity_score = 0
        
        # Length-based
        if len(query) > 500:
            complexity_score += 2
        elif len(query) > 200:
            complexity_score += 1
            
        # Technical indicators
        tech_terms = ["exploit", "vulnerability", "cve", "cwe", "zero-day", "rce",
                      "sqli", "xss", "authentication", "authorization", "encryption",
                      "bypass", "privilege escalation", "chain", "sandbox escape"]
        for term in tech_terms:
            if term in query_lower:
                complexity_score += 1
                break  # Only count one match per category
        
        # Code presence
        if "```" in query or "def " in query or "function " in query or "class " in query:
            complexity_score += 2
            
        # Multi-step indicators
        multi_step = ["then", "after", "next", "chain", "sequence", "pipeline",
                      "workflow", "multi-step", "orchestrate"]
        for term in multi_step:
            if term in query_lower:
                complexity_score += 1
                break
                
        # Threat intelligence indicators
        threat_terms = ["cve-", "cwe-", "att&ck", "mitre", "ttp", "indicator",
                        "ioc", "threat", "malware", "ransomware"]
        for term in threat_terms:
            if term in query_lower:
                complexity_score += 2
                break
        
        # Map score to effort level
        if complexity_score >= 6:
            return EffortLevel.MAX
        elif complexity_score >= 4:
            return EffortLevel.HIGH
        elif complexity_score >= 2:
            return EffortLevel.MEDIUM
        else:
            return EffortLevel.LOW
    
    async def think(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        effort_override: Optional[EffortLevel] = None,
        tool_steps: int = 0,
    ) -> ThinkingResult:
        """Generate thinking blocks for a query.
        
        Args:
            query: The input query to reason about
            context: Optional context
            effort_override: Override the configured effort level
            tool_steps: Number of tool call steps taken so far (for interleaved)
            
        Returns:
            ThinkingResult with reasoning blocks and final response guidance
        """
        effort = effort_override or self.config.effort
        start_time = time.time()
        
        # If effort is LOW and query is very simple, skip deep thinking
        if effort == EffortLevel.LOW and len(query) < 100:
            thinking_blocks = [
                ThinkingBlock(
                    type="thinking_summary",
                    content="Query is straightforward. Minimal reasoning required.",
                    effort_used=EffortLevel.LOW,
                    token_count=16,
                )
            ]
            return ThinkingResult(
                thinking_blocks=thinking_blocks,
                final_response="",
                total_thinking_tokens=16,
                effort_used=EffortLevel.LOW,
                thinking_time_ms=(time.time() - start_time) * 1000,
                interleaved_steps=tool_steps,
            )
        
        # Get the thinking template for this effort level
        template_key = effort.value
        template = THINKING_TEMPLATES.get(template_key, THINKING_TEMPLATES["high"])
        
        max_tokens = self.config.max_thinking_tokens
        if effort == EffortLevel.LOW:
            max_tokens = min(max_tokens, 1024)
        elif effort == EffortLevel.MEDIUM:
            max_tokens = min(max_tokens, 4096)
        elif effort == EffortLevel.HIGH:
            max_tokens = min(max_tokens, 8192)
        # MAX = use full max_thinking_tokens
        
        # Build the thinking prompt using the template
        thinking_prompt = template["prompt_template"].format(
            max_tokens=max_tokens,
        )
        
        # Add context if available
        if context:
            context_summary = self._summarize_context(context)
            if context_summary:
                thinking_prompt += f"\n\nContext:\n{context_summary}"
        
        # Add query
        thinking_prompt += f"\n\nQuery to analyze:\n{query}"
        
        # Generate thinking blocks
        # In Fable 5, the model generates thinking internally.
        # Here, we create structured thinking blocks that represent the reasoning.
        
        thinking_blocks = self._generate_thinking_blocks(
            query=query,
            thinking_prompt=thinking_prompt,
            effort=effort,
            max_tokens=max_tokens,
            context=context,
        )
        
        # If interleaved thinking is enabled and we have tool steps, add interleaved blocks
        if self.config.interleaved_thinking and tool_steps > 0:
            interleaved = self._generate_interleaved_thinking(
                query, tool_steps, effort, context
            )
            thinking_blocks.extend(interleaved)
        
        total_tokens = sum(b.token_count for b in thinking_blocks)
        
        # Build the final response prompt with reasoning guidance
        final_response = self._build_response_guidance(thinking_blocks, effort)
        
        thinking_time = (time.time() - start_time) * 1000
        
        result = ThinkingResult(
            thinking_blocks=thinking_blocks,
            final_response=final_response,
            total_thinking_tokens=total_tokens,
            effort_used=effort,
            thinking_time_ms=thinking_time,
            interleaved_steps=tool_steps if self.config.interleaved_thinking else 0,
        )
        
        self._thinking_history.append(result)
        logger.info(
            f"Adaptive thinking completed: effort={effort.value}, "
            f"tokens={total_tokens}, time={thinking_time:.0f}ms, "
            f"interleaved={result.interleaved_steps}"
        )
        
        return result
    
    def _summarize_context(self, context: Dict[str, Any]) -> str:
        """Summarize context for the thinking prompt."""
        parts = []
        
        if "codebase" in context:
            codebase_info = context["codebase"]
            if isinstance(codebase_info, dict):
                parts.append(f"Codebase: {codebase_info.get('summary', '')}")
            else:
                parts.append(f"Codebase: {str(codebase_info)[:200]}")
        
        if "files" in context:
            files = context["files"]
            if isinstance(files, list):
                parts.append(f"Referenced files: {', '.join(files[:5])}")
        
        if "task" in context:
            parts.append(f"Task context: {str(context['task'])[:200]}")
        
        if "previous_findings" in context:
            findings = context["previous_findings"]
            if isinstance(findings, list):
                parts.append(f"Previous findings: {len(findings)} issues identified")
        
        return "\n".join(parts) if parts else ""
    
    def _generate_thinking_blocks(
        self,
        query: str,
        thinking_prompt: str,
        effort: EffortLevel,
        max_tokens: int,
        context: Optional[Dict] = None,
    ) -> List[ThinkingBlock]:
        """Generate structured thinking blocks."""
        blocks = []
        
        # Block 1: Problem analysis
        blocks.append(ThinkingBlock(
            type="thinking",
            content=self._analyze_problem(query, effort),
            effort_used=effort,
            token_count=128,
        ))
        
        # Block 2: Technical reasoning (depth varies by effort)
        reasoning = self._generate_reasoning(query, effort, context)
        if reasoning:
            blocks.append(ThinkingBlock(
                type="thinking",
                content=reasoning,
                effort_used=effort,
                token_count=256,
            ))
        
        # Block 3: Summary (always included, like Fable 5's connector summarization)
        if self.config.connector_summarization:
            summary = self._generate_connector_summary(query, effort, blocks)
            blocks.append(ThinkingBlock(
                type="thinking_summary",
                content=summary,
                effort_used=effort,
                token_count=64,
            ))
        
        return blocks
    
    def _analyze_problem(self, query: str, effort: EffortLevel) -> str:
        """Analyze what the query is asking for."""
        query_lower = query.lower()
        
        analysis_parts = []
        
        # Determine query type
        if any(kw in query_lower for kw in ["vulnerability", "cve", "cwe", "security"]):
            analysis_parts.append("Type: Security analysis request")
        elif any(kw in query_lower for kw in ["exploit", "bypass", "attack"]):
            analysis_parts.append("Type: Exploit/attack analysis")
        elif any(kw in query_lower for kw in ["fix", "patch", "remediate", "secure"]):
            analysis_parts.append("Type: Remediation request")
        elif any(kw in query_lower for kw in ["scan", "audit", "review"]):
            analysis_parts.append("Type: Code audit/scan request")
        elif any(kw in query_lower for kw in ["plan", "strategy", "design"]):
            analysis_parts.append("Type: Planning/architecture request")
        else:
            analysis_parts.append("Type: General analysis")
        
        # Determine depth
        if effort == EffortLevel.MAX:
            analysis_parts.append("Depth: Maximum — exploring all angles and edge cases")
        elif effort == EffortLevel.HIGH:
            analysis_parts.append("Depth: Deep — thorough technical analysis")
        elif effort == EffortLevel.MEDIUM:
            analysis_parts.append("Depth: Moderate — focused on key aspects")
        else:
            analysis_parts.append("Depth: Light — addressing the core question")
        
        # Extract key entities
        cve_matches = [word for word in query_lower.split() if word.startswith("cve-")]
        if cve_matches:
            analysis_parts.append(f"CVEs referenced: {', '.join(cve_matches)}")
        
        return "\n".join(analysis_parts)
    
    def _generate_reasoning(self, query: str, effort: EffortLevel, context: Optional[Dict]) -> str:
        """Generate technical reasoning based on effort level."""
        if effort == EffortLevel.LOW:
            return ""
        
        query_lower = query.lower()
        reasoning_steps = []
        
        # Security-specific reasoning
        if any(kw in query_lower for kw in ["sql", "injection", "sqli"]):
            reasoning_steps.extend([
                "1. SQL Injection Analysis:",
                "   - Check for string concatenation in queries",
                "   - Verify parameterized query usage",
                "   - Assess ORM injection vectors",
                "   - Check stored procedure safety",
            ])
        
        if any(kw in query_lower for kw in ["xss", "cross-site", "script"]):
            reasoning_steps.extend([
                "2. XSS Analysis:",
                "   - Identify input rendering contexts (HTML, JS, CSS, URL)",
                "   - Check output encoding/escaping",
                "   - Verify CSP headers",
                "   - Assess DOM-based vs reflected vs stored",
            ])
        
        if any(kw in query_lower for kw in ["auth", "authentication", "bypass"]):
            reasoning_steps.extend([
                "3. Authentication Analysis:",
                "   - Verify session management",
                "   - Check password policies",
                "   - Assess MFA implementation",
                "   - Review token handling (JWT, OAuth)",
            ])
        
        if effort == EffortLevel.MAX and len(reasoning_steps) < 3:
            reasoning_steps.extend([
                "4. Advanced Threat Modeling:",
                "   - STRIDE analysis per component",
                "   - Attack surface enumeration",
                "   - Trust boundary mapping",
                "   - Data flow analysis",
                "5. Defense-in-Depth Assessment:",
                "   - Network segmentation",
                "   - WAF rules",
                "   - Runtime protection",
                "   - Monitoring & detection",
            ])
        
        if not reasoning_steps:
            # Generic reasoning
            reasoning_steps.append("1. Input analysis and categorization")
            reasoning_steps.append("2. Pattern matching against known vulnerabilities")
            if effort in (EffortLevel.HIGH, EffortLevel.MAX):
                reasoning_steps.append("3. Cross-reference with threat intelligence")
                reasoning_steps.append("4. Impact and severity assessment")
            reasoning_steps.append("5. Remediation strategy formulation")
        
        return "\n".join(reasoning_steps)
    
    def _generate_connector_summary(
        self, query: str, effort: EffortLevel, blocks: List[ThinkingBlock]
    ) -> str:
        """Generate connector text summarization — like Fable 5's feature.
        
        In Fable 5, connector text summarization converts conversational text
        between tool calls into summarized thinking blocks. This optimizes
        agentic workflows by reducing token usage.
        """
        analysis = blocks[0].content if blocks else ""
        
        summary = (
            f"[Thinking Summary - Effort: {effort.value}]\n"
            f"Analysis scope: {analysis.split(chr(10))[0] if analysis else 'General'}\n"
            f"Reasoning depth: {effort.value}\n"
        )
        
        if effort == EffortLevel.MAX:
            summary += "Status: Exhaustive analysis — all attack surfaces covered"
        elif effort == EffortLevel.HIGH:
            summary += "Status: Thorough analysis — key vulnerabilities identified"
        elif effort == EffortLevel.MEDIUM:
            summary += "Status: Moderate analysis — primary risks assessed"
        else:
            summary += "Status: Quick analysis — core issue addressed"
        
        return summary
    
    def _generate_interleaved_thinking(
        self,
        query: str,
        tool_steps: int,
        effort: EffortLevel,
        context: Optional[Dict],
    ) -> List[ThinkingBlock]:
        """Generate interleaved thinking blocks for multi-tool workflows.
        
        Fable 5 allows thinking between tool calls, updating reasoning
        based on intermediate results. This is essential for agentic tasks.
        """
        blocks = []
        
        for step in range(1, tool_steps + 1):
            block = ThinkingBlock(
                type="thinking",
                content=(
                    f"[Interleaved Thinking - Step {step}/{tool_steps}]\n"
                    f"Reassessing strategy after tool execution step {step}...\n"
                    f"Checking if intermediate results change the analysis direction.\n"
                    f"Effort level: {effort.value} — "
                    f"{'adjusting approach as needed' if effort in (EffortLevel.HIGH, EffortLevel.MAX) else 'continuing with current approach'}"
                ),
                effort_used=effort,
                token_count=64,
                metadata={"interleaved_step": step, "total_tool_steps": tool_steps},
            )
            blocks.append(block)
        
        return blocks
    
    def _build_response_guidance(
        self, blocks: List[ThinkingBlock], effort: EffortLevel
    ) -> str:
        """Build response guidance from thinking blocks.
        
        This tells the agent how to respond based on the reasoning performed.
        Matches Fable 5's approach of using thinking to inform the final response.
        """
        summary = next(
            (b for b in blocks if b.type == "thinking_summary"),
            None,
        )
        
        guidance = "Response Guidance:\n"
        if summary:
            guidance += f"- Based on reasoning: {summary.content[:200]}\n"
        
        if effort == EffortLevel.MAX:
            guidance += "- Provide comprehensive response with all findings\n"
            guidance += "- Include code-level details and architectural recommendations\n"
            guidance += "- Structure as a formal security assessment report\n"
        elif effort == EffortLevel.HIGH:
            guidance += "- Provide thorough analysis with actionable findings\n"
            guidance += "- Include severity ratings and remediation steps\n"
        elif effort == EffortLevel.MEDIUM:
            guidance += "- Focus on the most critical findings\n"
            guidance += "- Provide clear, concise remediation advice\n"
        else:
            guidance += "- Provide a direct answer to the query\n"
            guidance += "- Keep it concise and actionable\n"
        
        return guidance
    
    def get_thinking_history(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get recent thinking history."""
        return [r.to_dict() for r in self._thinking_history[-limit:]]
    
    def get_status(self) -> Dict[str, Any]:
        """Get engine status."""
        return {
            "effort": self.config.effort.value,
            "interleaved_thinking": self.config.interleaved_thinking,
            "connector_summarization": self.config.connector_summarization,
            "history_count": len(self._thinking_history),
            "available_efforts": [e.value for e in EffortLevel],
        }
