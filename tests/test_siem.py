"""Tests for SIEM integration (Splunk HEC, Elasticsearch, CEF output)."""

import os
import sys
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestSIEMEvent:
    """Test SIEMEvent formatting for different outputs."""

    def test_create_event_defaults(self):
        """Test creating a SIEM event with default values."""
        from src.integrations.siem import SIEMForwarder, SIEMEvent

        siem = SIEMForwarder()
        event = siem.create_event(
            title="SQL Injection",
            description="Found SQL injection in login endpoint",
            severity="CRITICAL",
            source="Code-Scanner",
            category="vulnerability",
        )

        assert event.title == "SQL Injection"
        assert event.severity == "CRITICAL"
        assert event.source == "Code-Scanner"
        assert event.category == "vulnerability"
        assert "sentinel" in event.tags

    def test_create_event_with_finding(self):
        """Test creating a SIEM event from a finding dict."""
        from src.integrations.siem import findings_to_siem_events

        result = {
            "findings": [
                {"title": "XSS", "description": "Cross-site scripting", "severity": "HIGH",
                 "agent": "Scanner", "cwe": "CWE-79", "tags": ["xss"]},
                {"title": "SQLi", "description": "SQL injection", "severity": "CRITICAL",
                 "agent": "Scanner", "cwe": "CWE-89"},
            ]
        }

        events = findings_to_siem_events(result)
        assert len(events) == 2
        assert events[0].title == "XSS"
        assert events[0].cwe_id == "CWE-79"
        assert events[1].severity == "CRITICAL"

    def test_to_splunk_hec(self):
        """Test Splunk HEC format."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        event = siem.create_event("SQLi", "SQL injection", "HIGH", "scanner")
        hec = event.to_splunk_hec()

        assert "event" in hec
        assert hec["sourcetype"] == "sentinel:security:alert"
        assert hec["event"]["title"] == "SQLi"
        assert hec["event"]["severity"] == "HIGH"

    def test_to_elasticsearch(self):
        """Test Elasticsearch format."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        event = siem.create_event("XSS", "Cross-site scripting", "MEDIUM", "scanner",
                                  cwe_id="CWE-79")
        es = event.to_elasticsearch()

        assert "@timestamp" in es
        assert es["event"]["severity"] == "MEDIUM"
        assert es["sentinel"]["cwe_id"] == "CWE-79"

    def test_to_cef(self):
        """Test CEF format for legacy SIEM."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        event = siem.create_event("RCE", "Remote code execution", "CRITICAL",
                                  "exploit-analyzer", category="exploit")
        cef = event.to_cef()

        assert cef.startswith("CEF:0|Sentinel|CyberAI|2.0|SECURITY_ALERT|")
        assert "RCE" in cef
        assert "CRITICAL" in cef or "10" in cef

    def test_to_json_log(self):
        """Test JSON log line format for Logstash/Filebeat."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        event = siem.create_event("Test", "Description", "LOW", "test")
        log_line = event.to_json_log()

        parsed = json.loads(log_line)
        assert parsed["title"] == "Test"
        assert parsed["severity"] == "LOW"
        assert parsed["asset"] == "sentinel"

    def test_agent_result_to_siem(self):
        """Test converting agent result to SIEM event."""
        from src.integrations.siem import agent_result_to_siem_event

        agent_result = {
            "agent_name": "Code-Scanner",
            "status": "success",
            "confidence": 0.95,
            "summary": "Found SQL injection vulnerability",
        }

        event = agent_result_to_siem_event(agent_result)
        assert event.source == "Code-Scanner"
        assert event.severity == "HIGH"  # confidence > 0.8
        assert "SQL injection" in event.description


class TestSIEMForwarder:
    """Test SIEM forwarder configuration and buffering."""

    def test_configure_splunk(self):
        """Test Splunk HEC configuration."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        siem.configure_splunk("test-token", "https://splunk:8088/services/collector")

        stats = siem.get_stats()
        assert stats["splunk_configured"] is True

    def test_configure_elasticsearch(self):
        """Test Elasticsearch configuration."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        siem.configure_elasticsearch(hosts=["http://localhost:9200"])

        stats = siem.get_stats()
        assert stats["elasticsearch_configured"] is True

    def test_configure_log_file(self):
        """Test log file configuration creates directory."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        siem.configure_log_file("/tmp/test_siem_log.json")

        stats = siem.get_stats()
        assert stats["log_file_configured"] is True

    def test_stats_defaults(self):
        """Test stats returns defaults when nothing configured."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        stats = siem.get_stats()

        assert stats["forwarded"] == 0
        assert stats["failed"] == 0
        assert stats["buffered"] == 0

    @patch("src.integrations.siem.SIEMForwarder._write_log_file")
    def test_flush_with_log_file(self, mock_write):
        """Test flushing events to log file."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        siem.configure_log_file("/tmp/test.json")

        event = siem.create_event("Test", "Test", "INFO", "test")
        siem._event_buffer.append(event)

        import asyncio
        asyncio.run(siem.flush())

        mock_write.assert_called_once()
        assert siem.get_stats()["forwarded"] == 1

    def test_forward_finding_no_config(self):
        """Test forward_finding silently succeeds with no config."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        import asyncio
        result = asyncio.run(siem.forward_finding({
            "title": "Test", "description": "Test", "severity": "LOW"
        }))
        assert result is True  # No config = no error

    def test_cef_severity_mapping(self):
        """Test CEF severity mapping for various severities."""
        from src.integrations.siem import SIEMForwarder

        siem = SIEMForwarder()
        severities = {
            "CRITICAL": "10", "HIGH": "8", "MEDIUM": "6",
            "LOW": "3", "INFO": "1",
        }

        for sev, expected in severities.items():
            event = siem.create_event("T", "D", sev, "test")
            cef = event.to_cef()
            assert expected in cef
