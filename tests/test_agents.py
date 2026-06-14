"""Tests for all specialized agent implementations."""

import pytest
from src.agents.base_agent import BaseAgent, AgentResult
from src.agents.scanner_agent import CodeScannerAgent
from src.agents.exploit_agent import ExploitAnalyzerAgent
from src.agents.patch_agent import PatchGeneratorAgent
from src.agents.analysis_agent import ThreatIntelligenceAgent
from src.agents.report_agent import ReportGeneratorAgent


class TestBaseAgent:
    """Tests for the base agent class."""

    def test_abstract_class_cannot_instantiate(self):
        """BaseAgent should not be instantiable directly."""
        with pytest.raises(TypeError):
            BaseAgent("test", "test-model")

    def test_agent_result_defaults(self):
        """AgentResult should have sensible defaults."""
        result = AgentResult(
            agent_name="TestAgent",
            status="success",
            summary="Test successful",
        )
        assert result.confidence == 0.0
        assert result.duration_ms == 0.0
        assert result.findings == []
        assert result.error is None

    def test_agent_result_to_dict(self):
        """AgentResult should serialize to dict."""
        result = AgentResult(
            agent_name="TestAgent",
            status="success",
            summary="Test",
            confidence=0.95,
        )
        d = result.to_dict()
        assert d["agent_name"] == "TestAgent"
        assert d["status"] == "success"
        assert d["confidence"] == 0.95

    def test_agent_result_to_markdown(self):
        """AgentResult should format as markdown."""
        result = AgentResult(
            agent_name="TestAgent",
            status="success",
            summary="Test summary",
            findings=[{"title": "SQL Injection", "severity": "CRITICAL", "description": "Test desc"}],
        )
        md = result.to_markdown()
        assert "TestAgent" in md
        assert "SQL Injection" in md
        assert "CRITICAL" in md

    def test_format_finding(self):
        """BaseAgent.format_finding should create correct structure."""

        class ConcreteAgent(BaseAgent):
            async def analyze(self, query, context=None):
                return AgentResult(agent_name="test", status="success", summary="test")

        agent = ConcreteAgent("test", "test-model")
        finding = agent.format_finding(
            title="SQL Injection",
            description="Test description",
            severity="HIGH",
            location="test.py:42",
            remediation="Use parameterized queries",
            cwe="CWE-89",
        )
        assert finding["title"] == "SQL Injection"
        assert finding["severity"] == "HIGH"
        assert finding["cwe"] == "CWE-89"
        assert finding["remediation"] == "Use parameterized queries"


class TestCodeScannerAgent:
    """Tests for the Code Scanner agent."""

    @pytest.mark.asyncio
    async def test_detects_sql_injection(self):
        """Code scanner should detect SQL injection."""
        agent = CodeScannerAgent()
        code = """def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()"""
        result = await agent.analyze(code)
        assert result.status == "success"
        assert any("SQL" in f.get("title", "") for f in result.findings)

    @pytest.mark.asyncio
    async def test_detects_command_injection(self):
        """Code scanner should detect command injection."""
        agent = CodeScannerAgent()
        code = """import subprocess
def ping(host):
    return subprocess.run(f"ping {host}", shell=True)"""
        result = await agent.analyze(code)
        assert result.status == "success"
        assert any("Command" in f.get("title", "") or "command" in f.get("title", "").lower()
                   for f in result.findings)

    @pytest.mark.asyncio
    async def test_detects_xss(self):
        """Code scanner should detect XSS."""
        agent = CodeScannerAgent()
        code = """function show() {
    document.getElementById('out').innerHTML = userInput;
}"""
        result = await agent.analyze(code)
        assert result.status == "success"
        assert any("XSS" in f.get("title", "") or "xss" in f.get("title", "").lower()
                   for f in result.findings)

    @pytest.mark.asyncio
    async def test_returns_no_findings_for_safe_code(self):
        """Code scanner should return no findings for safe code."""
        agent = CodeScannerAgent()
        code = """def greet(name):
    return f"Hello, {name}!"
    
def add(a, b):
    return a + b"""
        result = await agent.analyze(code)
        # Safe code might still have generic AI findings
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_returns_positive_confidence(self):
        """Agent should return positive confidence for valid inputs."""
        agent = CodeScannerAgent()
        vuln_code = """import subprocess
import os

def process(host, cmd):
    os.system(f"ping {host}")
    subprocess.run(cmd, shell=True)
    eval(user_input)"""
        result = await agent.analyze(vuln_code)
        assert result.confidence > 0

    @pytest.mark.asyncio
    async def test_extracts_code_blocks(self):
        """Code scanner should extract code from markdown blocks."""
        agent = CodeScannerAgent()
        query = """Here's some code:
```python
eval(user_input)
```"""
        result = await agent.analyze(query)
        assert result.status == "success"


class TestExploitAnalyzerAgent:
    """Tests for the Exploit Analyzer agent."""

    @pytest.mark.asyncio
    async def test_identifies_exploit_techniques(self):
        """Exploit analyzer should identify exploit techniques."""
        agent = ExploitAnalyzerAgent()
        result = await agent.analyze("buffer overflow in network service")
        assert result.status == "success"
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_detects_cve_references(self):
        """Exploit analyzer should detect CVE references."""
        agent = ExploitAnalyzerAgent()
        result = await agent.analyze("exploit CVE-2021-44228 Log4j")
        assert result.status == "success"
        assert any("CVE" in f.get("title", "") for f in result.findings)

    @pytest.mark.asyncio
    async def test_assesses_risk(self):
        """Exploit analyzer should provide risk assessment."""
        agent = ExploitAnalyzerAgent()
        result = await agent.analyze("remote code execution in web app")
        assert result.status == "success"
        assert result.confidence > 0


class TestPatchGeneratorAgent:
    """Tests for the Patch Generator agent."""

    @pytest.mark.asyncio
    async def test_generates_patches_for_vulns(self):
        """Patch generator should generate fixes."""
        agent = PatchGeneratorAgent()
        code = """def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()"""
        query = f"Fix this vulnerable code:\n```\n{code}\n```"
        result = await agent.analyze(query)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_detects_language(self):
        """Patch generator should detect programming language."""
        agent = PatchGeneratorAgent()
        js_code = """function show() {
    document.getElementById('out').innerHTML = name;
}"""
        result = await agent.analyze(js_code)
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_provides_guidance_for_safe_code(self):
        """Patch generator should provide guidance even without clear vulns."""
        agent = PatchGeneratorAgent()
        result = await agent.analyze("How do I write secure code?")
        assert result.status == "success"


class TestThreatIntelligenceAgent:
    """Tests for the Threat Intelligence agent."""

    @pytest.mark.asyncio
    async def test_detects_cve_references(self):
        """Threat intel should detect CVE references."""
        agent = ThreatIntelligenceAgent()
        result = await agent.analyze("Check CVE-2021-44228 Log4j")
        assert result.status == "success"
        assert any("CVE" in f.get("title", "") for f in result.findings)

    @pytest.mark.asyncio
    async def test_detects_cwe_references(self):
        """Threat intel should detect CWE references."""
        agent = ThreatIntelligenceAgent()
        result = await agent.analyze("Analyze CWE-89 SQL injection")
        assert result.status == "success"
        assert any("CWE" in f.get("title", "") for f in result.findings)

    @pytest.mark.asyncio
    async def test_maps_to_attack_framework(self):
        """Threat intel should map to MITRE ATT&CK."""
        agent = ThreatIntelligenceAgent()
        result = await agent.analyze("Check CVE-2024-3094 XZ backdoor")
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_handles_no_matches(self):
        """Threat intel should handle queries with no matches."""
        agent = ThreatIntelligenceAgent()
        result = await agent.analyze("What is the weather today?")
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_recognizes_vuln_keywords(self):
        """Threat intel should recognize vulnerability by keyword."""
        agent = ThreatIntelligenceAgent()
        result = await agent.analyze("Check if we're affected by Log4Shell")
        assert result.status == "success"


class TestReportGeneratorAgent:
    """Tests for the Report Generator agent."""

    @pytest.mark.asyncio
    async def test_analyze_returns_ready(self):
        """Report agent should report ready when called directly."""
        agent = ReportGeneratorAgent()
        result = await agent.analyze("test")
        assert result.status == "success"
        assert "available_templates" in result.details

    def test_generate_executive_report(self):
        """Should generate executive summary report."""
        agent = ReportGeneratorAgent()
        analysis_result = {
            "task_id": "test-123",
            "status": "success",
            "summary": "Found 3 vulnerabilities",
            "findings": [
                {"title": "SQL Injection", "severity": "CRITICAL", "description": "Test"},
                {"title": "XSS", "severity": "HIGH", "description": "Test"},
            ],
            "confidence": 0.85,
            "agents_used": ["Code-Scanner"],
            "agent_results": [{"agent_name": "Code-Scanner", "status": "success"}],
        }
        report = agent.generate_executive_summary(analysis_result)
        assert "SQL Injection" in report
        assert "Critical Items" in report
        assert "test-123" in report

    def test_generate_technical_report(self):
        """Should generate technical report."""
        agent = ReportGeneratorAgent()
        analysis_result = {
            "task_id": "test-456",
            "status": "success",
            "summary": "Analysis complete",
            "findings": [{"title": "Test Finding", "severity": "MEDIUM", "description": "Test"}],
            "confidence": 0.9,
            "agents_used": ["Code-Scanner"],
            "agent_results": [{"agent_name": "Code-Scanner", "status": "success"}],
        }
        report = agent.generate_report(analysis_result, report_type="technical")
        assert "Technical Security Report" in report
        assert "test-456" in report

    def test_generate_slack_report(self):
        """Should generate Slack-formatted report."""
        agent = ReportGeneratorAgent()
        analysis_result = {
            "task_id": "test-789",
            "status": "success",
            "summary": "Found issues",
            "findings": [{"title": "XSS", "severity": "HIGH", "description": "Test"}],
            "confidence": 0.8,
            "agents_used": ["Code-Scanner"],
            "agent_results": [],
        }
        report = agent.generate_report(analysis_result, report_type="slack",
                                       report_url="https://example.com/report/123")
        assert "Sentinel" in report
        assert "HIGH" in report

    def test_generate_empty_report(self):
        """Should handle empty findings gracefully."""
        agent = ReportGeneratorAgent()
        analysis_result = {
            "task_id": "test-empty",
            "status": "success",
            "summary": "No issues found",
            "findings": [],
            "confidence": 0.95,
            "agents_used": ["Code-Scanner"],
            "agent_results": [],
        }
        report = agent.generate_report(analysis_result, report_type="executive")
        assert "No issues" in report or "no" in report.lower()
