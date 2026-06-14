"""Tests for the auto-remediation pipeline (fix generation + PR creation)."""

import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestAutoRemediationEngine:
    """Test the auto-remediation pipeline."""

    def test_init_defaults(self):
        """Test engine initializes with defaults."""
        os.environ.pop("AUTO_REMEDIATION_ENABLED", None)
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        assert engine._enabled is False
        assert engine._branch_prefix == "sentinel-fix/"
        assert engine._remediations == []
        assert engine._prs == []

    def test_init_with_orchestrator(self):
        """Test engine initializes with orchestrator."""
        from src.integrations.auto_remediation import AutoRemediationEngine

        mock_orc = MagicMock()
        engine = AutoRemediationEngine(mock_orc)
        assert engine._orchestrator is mock_orc

    def test_enabled_flag(self):
        """Test engine respects AUTO_REMEDIATION_ENABLED env var."""
        os.environ["AUTO_REMEDIATION_ENABLED"] = "true"
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        assert engine._enabled is True

    def test_engine_disabled_returns_none(self):
        """Test remediate_finding returns None when disabled."""
        os.environ["AUTO_REMEDIATION_ENABLED"] = "false"
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        import asyncio
        result = asyncio.run(engine.remediate_finding(
            {"title": "Test"}, "user/repo"
        ))
        assert result is None

    @patch("src.integrations.auto_remediation.AutoRemediationEngine._extract_fixed_code")
    def test_remediate_finding_success(self, mock_extract):
        """Test successful remediation with fix generation."""
        os.environ["AUTO_REMEDIATION_ENABLED"] = "true"
        from src.integrations.auto_remediation import AutoRemediationEngine

        mock_orc = MagicMock()
        mock_orc.process = AsyncMock(return_value={
            "status": "success",
            "summary": "Fixed the vulnerability",
        })
        mock_extract.return_value = "def safe_function(): pass"

        engine = AutoRemediationEngine(mock_orc)

        import asyncio
        remediation = asyncio.run(engine.remediate_finding(
            {"id": "finding-1", "title": "SQL Injection",
             "description": "SQL injection in query", "severity": "CRITICAL"},
            "user/repo",
            file_path="src/app.py",
            source_code="def unsafe(): pass",
        ))

        assert remediation is not None
        assert remediation.status == "applied"
        assert remediation.fixed_content == "def safe_function(): pass"
        assert remediation.severity == "CRITICAL"
        assert remediation.file_path == "src/app.py"

    @patch("src.integrations.auto_remediation.AutoRemediationEngine._extract_fixed_code")
    def test_remediate_finding_no_fix(self, mock_extract):
        """Test remediation handles no fix generated gracefully."""
        os.environ["AUTO_REMEDIATION_ENABLED"] = "true"
        from src.integrations.auto_remediation import AutoRemediationEngine

        mock_orc = MagicMock()
        mock_orc.process = AsyncMock(return_value={"status": "success"})
        mock_extract.return_value = None

        engine = AutoRemediationEngine(mock_orc)

        import asyncio
        remediation = asyncio.run(engine.remediate_finding(
            {"id": "finding-2", "title": "Test", "description": "Test"},
            "user/repo",
            source_code="original code",
        ))

        assert remediation is not None
        assert remediation.status == "failed"
        assert "No fix" in remediation.error

    def test_extract_fixed_code_from_code_block(self):
        """Test extracting fixed code from markdown code block."""
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        result = {
            "summary": "Here's the fix:\n```python\ndef fixed(): pass\n```\nFixed!"
        }

        code = engine._extract_fixed_code(result, "original")
        assert code == "def fixed(): pass"

    def test_extract_fixed_code_from_finding(self):
        """Test extracting fixed code from finding fixed_code field."""
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        result = {
            "status": "success",
            "findings": [{"fixed_code": "def fixed(): return True"}]
        }

        code = engine._extract_fixed_code(result, "original")
        assert code == "def fixed(): return True"

    def test_extract_fixed_code_from_response(self):
        """Test using raw response as fixed code."""
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        result = {"response": "def fixed(): pass"}

        code = engine._extract_fixed_code(result, "original")
        assert code == "def fixed(): pass"

    def test_extract_fixed_code_empty(self):
        """Test extract returns None for empty response."""
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        assert engine._extract_fixed_code({}, "original") is None

    def test_build_pr_body(self):
        """Test PR body generation."""
        from src.integrations.auto_remediation import (
            AutoRemediationEngine, Remediation
        )

        engine = AutoRemediationEngine()
        remediations = [
            Remediation(
                id="rem-1", finding_id="f-1", file_path="src/app.py",
                original_content="bad", fixed_content="good",
                description="SQL Injection", severity="CRITICAL",
                status="applied",
            ),
            Remediation(
                id="rem-2", finding_id="f-2", file_path="src/utils.py",
                original_content="old", fixed_content="new",
                description="XSS vulnerability", severity="HIGH",
                status="applied",
            ),
        ]

        body = engine._build_pr_body(remediations, "user/repo", "sentinel-fix/test")
        assert "user/repo" in body
        assert "SQL Injection" in body
        assert "XSS vulnerability" in body
        assert "CRITICAL" in body
        assert "HIGH" in body
        assert "sentinel-fix/test" in body

    def test_get_stats(self):
        """Test stats returns correct counts."""
        os.environ["AUTO_REMEDIATION_ENABLED"] = "true"
        from src.integrations.auto_remediation import AutoRemediationEngine

        engine = AutoRemediationEngine()
        engine._remediations = [
            MagicMock(status="applied"),
            MagicMock(status="failed"),
            MagicMock(status="applied"),
        ]
        engine._prs = [MagicMock(status="created")]

        stats = engine.get_stats()
        assert stats["total_remediations"] == 3
        assert stats["remediation_statuses"]["applied"] == 2
        assert stats["remediation_statuses"]["failed"] == 1
        assert stats["prs_created"] == 1


class TestRemediationDataClasses:
    """Test the data classes used by auto-remediation."""

    def test_remediation_defaults(self):
        """Test Remediation dataclass default values."""
        from src.integrations.auto_remediation import Remediation

        rem = Remediation(
            id="r-1", finding_id="f-1", file_path="src/app.py",
            original_content="old", fixed_content="new",
            description="Test", severity="HIGH",
        )
        assert rem.status == "pending"
        assert rem.cwe is None
        assert rem.error is None
        assert "created_at" in rem.__dict__

    def test_remediation_pr_defaults(self):
        """Test RemediationPR dataclass default values."""
        from src.integrations.auto_remediation import RemediationPR

        pr = RemediationPR(
            id="pr-1", branch="fix/test", title="Test PR",
            body="Description", remediations=[], repo="user/repo",
        )
        assert pr.status == "created"
        assert pr.pr_url is None
        assert pr.pr_number is None
        assert pr.error is None


class TestAutoRemediateFunction:
    """Test the high-level auto_remediate_finding function."""

    @patch("src.integrations.auto_remediation.AutoRemediationEngine.remediate_finding")
    @patch("src.integrations.auto_remediation.AutoRemediationEngine.create_remediation_pr")
    def test_auto_remediate_finding_full_pipeline(self, mock_create_pr, mock_remediate):
        """Test the full pipeline: finding → fix → PR."""
        from src.integrations.auto_remediation import auto_remediate_finding, Remediation

        os.environ["AUTO_REMEDIATION_ENABLED"] = "true"

        mock_remediate.return_value = Remediation(
            id="rem-1", finding_id="f-1", file_path="src/app.py",
            original_content="old", fixed_content="new",
            description="SQL Injection", severity="CRITICAL",
            status="applied",
        )
        mock_create_pr.return_value = MagicMock(
            pr_url="https://github.com/user/repo/pull/1"
        )

        mock_orc = MagicMock()
        import asyncio
        url = asyncio.run(auto_remediate_finding(
            mock_orc,
            {"id": "f-1", "title": "SQLi", "description": "SQL injection"},
            "user/repo",
            "src/app.py",
            "original code",
        ))

        assert url == "https://github.com/user/repo/pull/1"

    @patch("src.integrations.auto_remediation.AutoRemediationEngine.remediate_finding")
    def test_auto_remediate_finding_no_fix(self, mock_remediate):
        """Test function returns None when fix fails."""
        from src.integrations.auto_remediation import auto_remediate_finding

        os.environ["AUTO_REMEDIATION_ENABLED"] = "true"
        mock_remediate.return_value = None

        mock_orc = MagicMock()
        import asyncio
        url = asyncio.run(auto_remediate_finding(
            mock_orc, {"id": "f-1"}, "user/repo", "src/app.py", "code"
        ))
        assert url is None
