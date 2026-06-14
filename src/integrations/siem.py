"""
SIEM Integration — Splunk HEC & ELK (Elasticsearch, Logstash, Kibana) Output.

Sends Sentinel security findings and alerts to enterprise SIEM systems.
Supports:
1. Splunk HTTP Event Collector (HEC) — structured event ingestion
2. ELK/Elasticsearch — direct bulk index via Elasticsearch API
3. Logstash — JSON file output for Filebeat/Logstash ingestion
4. Standard syslog CEF format for legacy SIEM compatibility

Usage:
    from src.integrations.siem import SIEMForwarder

    siem = SIEMForwarder()
    siem.configure_splunk(hec_token="...", hec_endpoint="...")
    siem.configure_elasticsearch(hosts=["..."])

    # Forward findings
    await siem.forward_finding({"severity": "CRITICAL", "title": "SQL Injection"})
"""

import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class SIEMEvent:
    """Standardized security event for SIEM ingestion."""
    event_id: str
    title: str
    description: str
    severity: str
    source: str
    category: str
    timestamp: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    asset: str = "sentinel"
    mitre_technique: Optional[str] = None
    cwe_id: Optional[str] = None

    def to_splunk_hec(self) -> Dict:
        """Format as Splunk HEC event."""
        return {
            "event": {
                "title": self.title,
                "description": self.description,
                "severity": self.severity,
                "source": self.source,
                "category": self.category,
                "asset": self.asset,
                "findings": self.raw_data,
                "tags": self.tags,
                "mitre_technique": self.mitre_technique,
                "cwe_id": self.cwe_id,
            },
            "sourcetype": "sentinel:security:alert",
            "source": self.source,
            "host": self.asset,
            "time": datetime.fromisoformat(self.timestamp).timestamp(),
        }

    def to_elasticsearch(self) -> Dict:
        """Format as Elasticsearch document."""
        return {
            "@timestamp": self.timestamp,
            "event": {
                "id": self.event_id,
                "title": self.title,
                "description": self.description,
                "severity": self.severity,
                "category": self.category,
                "source": self.source,
            },
            "sentinel": {
                "asset": self.asset,
                "findings": self.raw_data,
                "tags": self.tags,
                "mitre_technique": self.mitre_technique,
                "cwe_id": self.cwe_id,
            },
        }

    def to_cef(self) -> str:
        """Format as CEF (Common Event Format) for syslog/Legacy SIEM.

        CEF:0|Sentinel|CyberAI|2.0|SECURITY_ALERT|title|severity|dvc=asset msg=description
        """
        severity_map = {
            "CRITICAL": "10", "HIGH": "8", "MEDIUM": "6",
            "LOW": "3", "INFO": "1",
        }
        cef_severity = severity_map.get(self.severity.upper(), "5")
        escaped_title = self.title.replace("|", "\\|").replace("=", "\\=")
        escaped_desc = self.description.replace("|", "\\|").replace("=", "\\=")[:200]

        return (
            f"CEF:0|Sentinel|CyberAI|2.0|SECURITY_ALERT|{escaped_title}|"
            f"{cef_severity}|dvc={self.asset} msg={escaped_desc} "
            f"cat={self.category} src={self.source}"
        )

    def to_json_log(self) -> str:
        """Format as JSON log line for Logstash/Filebeat."""
        doc = {
            "@timestamp": self.timestamp,
            "event_id": self.event_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description[:500],
            "source": self.source,
            "category": self.category,
            "asset": self.asset,
            "tags": self.tags,
        }
        return json.dumps(doc)


class SIEMForwarder:
    """Forwards Sentinel security events to enterprise SIEM systems.

    Supports:
    - Splunk HEC (HTTP Event Collector)
    - Elasticsearch bulk API
    - JSON log file (for Logstash/Filebeat)
    - CEF syslog format
    """

    def __init__(self):
        self._splunk_config: Dict = {}
        self._es_config: Dict = {}
        self._log_file: Optional[str] = None
        self._cef_enabled: bool = False
        self._event_buffer: List[SIEMEvent] = []
        self._buffer_size: int = 100
        self._flush_interval: float = 10.0  # seconds
        self._last_flush: float = time.time()
        self._forwarded_count: int = 0
        self._failed_count: int = 0

    # ── Configuration ──

    def configure_splunk(self, hec_token: str, hec_endpoint: str,
                          verify_ssl: bool = True, source: str = "sentinel"):
        """Configure Splunk HEC forwarding.

        Args:
            hec_token: Splunk HEC token
            hec_endpoint: Splunk HEC endpoint URL (e.g., https://splunk:8088/services/collector)
            verify_ssl: Verify SSL certificate
            source: Source label for events
        """
        self._splunk_config = {
            "token": hec_token,
            "endpoint": hec_endpoint.rstrip("/"),
            "verify_ssl": verify_ssl,
            "source": source,
        }
        logger.info(f"Configured Splunk HEC: {hec_endpoint}")

    def configure_elasticsearch(self, hosts: List[str], username: Optional[str] = None,
                                 password: Optional[str] = None,
                                 index_prefix: str = "sentinel-security",
                                 api_key: Optional[str] = None):
        """Configure Elasticsearch forwarding.

        Args:
            hosts: Elasticsearch hosts (e.g., ["http://localhost:9200"])
            username: Basic auth username
            password: Basic auth password
            index_prefix: Index name prefix (e.g., "sentinel-security-2024.01.01")
            api_key: API key authentication
        """
        self._es_config = {
            "hosts": hosts,
            "username": username,
            "password": password,
            "index_prefix": index_prefix,
            "api_key": api_key,
        }
        logger.info(f"Configured Elasticsearch: {hosts}")

    def configure_log_file(self, path: str = "logs/sentinel_siem.json"):
        """Configure JSON log file output for Logstash/Filebeat.

        Args:
            path: Path to JSON log file
        """
        self._log_file = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        logger.info(f"Configured SIEM log file: {path}")

    def enable_cef(self, enabled: bool = True):
        """Enable CEF syslog format output (logs to sentinel_cef.log)."""
        self._cef_enabled = enabled

    # ── Event Creation ──

    def create_event(self, title: str, description: str, severity: str,
                     source: str = "sentinel", category: str = "vulnerability",
                     raw_data: Optional[Dict] = None,
                     tags: Optional[List[str]] = None,
                     mitre_technique: Optional[str] = None,
                     cwe_id: Optional[str] = None) -> SIEMEvent:
        """Create a standardized SIEM event from Sentinel findings.

        Args:
            title: Event title
            description: Event description
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            source: Source component
            category: Event category
            raw_data: Raw finding data
            tags: Event tags
            mitre_technique: MITRE ATT&CK technique ID
            cwe_id: CWE ID for vulnerability classification

        Returns:
            SIEMEvent instance
        """
        return SIEMEvent(
            event_id=f"sentinel-{int(time.time())}-{hash(title) & 0xFFFF}",
            title=title,
            description=description,
            severity=severity,
            source=source,
            category=category,
            timestamp=datetime.utcnow().isoformat(),
            raw_data=raw_data or {},
            tags=tags or ["sentinel"],
            mitre_technique=mitre_technique,
            cwe_id=cwe_id,
        )

    # ── Forwarding ──

    async def forward_finding(self, finding: Dict) -> bool:
        """Forward a single security finding to all configured SIEM outputs.

        Args:
            finding: Security finding dict (from orchestrator result)

        Returns:
            True if forwarded successfully to at least one output
        """
        event = self.create_event(
            title=finding.get("title", "Security Finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "MEDIUM"),
            source=finding.get("agent", "scanner"),
            category=finding.get("category", "vulnerability"),
            raw_data=finding,
            tags=finding.get("tags", []),
            cwe_id=finding.get("cwe"),
            mitre_technique=finding.get("mitre_technique"),
        )

        self._event_buffer.append(event)
        success = await self._flush_if_needed()
        return success

    async def forward_alert(self, title: str, message: str, severity: str,
                            source: str = "sentinel", metadata: Optional[Dict] = None):
        """Forward an alert to all configured SIEM outputs.

        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity
            source: Alert source
            metadata: Additional metadata
        """
        event = self.create_event(
            title=title,
            description=message,
            severity=severity,
            source=source,
            category="alert",
            raw_data=metadata or {},
            tags=["alert", "sentinel"],
        )

        self._event_buffer.append(event)
        await self._flush_if_needed()

    async def flush(self) -> bool:
        """Flush buffered events to all configured outputs.

        Returns:
            True if all outputs received events successfully
        """
        if not self._event_buffer:
            return True

        events = self._event_buffer[:]
        self._event_buffer = []
        self._last_flush = time.time()

        success = True

        # Splunk HEC
        if self._splunk_config:
            splunk_ok = await self._forward_to_splunk(events)
            if not splunk_ok:
                success = False

        # Elasticsearch
        if self._es_config:
            es_ok = await self._forward_to_elasticsearch(events)
            if not es_ok:
                success = False

        # JSON log file
        if self._log_file:
            self._write_log_file(events)

        # CEF log
        if self._cef_enabled:
            self._write_cef_log(events)

        self._forwarded_count += len(events)
        return success

    async def _flush_if_needed(self) -> bool:
        """Flush if buffer is full or interval has elapsed."""
        if len(self._event_buffer) >= self._buffer_size:
            return await self.flush()
        if time.time() - self._last_flush >= self._flush_interval:
            return await self.flush()
        return True

    async def _forward_to_splunk(self, events: List[SIEMEvent]) -> bool:
        """Forward events to Splunk HEC."""
        try:
            import aiohttp

            url = f"{self._splunk_config['endpoint']}/event"
            headers = {
                "Authorization": f"Splunk {self._splunk_config['token']}",
                "Content-Type": "application/json",
            }

            success = True
            for event in events:
                payload = event.to_splunk_hec()
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            url, json=payload, headers=headers,
                            ssl=self._splunk_config.get("verify_ssl", True),
                            timeout=10,
                        ) as resp:
                            if resp.status not in (200, 201):
                                text = await resp.text()
                                logger.warning(f"Splunk HEC error: {resp.status} {text[:200]}")
                                success = False
                            else:
                                logger.debug(f"Forwarded to Splunk HEC: {event.event_id}")
                except Exception as e:
                    logger.error(f"Splunk HEC request failed: {e}")
                    success = False

            return success

        except ImportError:
            logger.warning("aiohttp not installed — can't forward to Splunk")
            return False
        except Exception as e:
            logger.error(f"Splunk forwarding failed: {e}")
            self._failed_count += len(events)
            return False

    async def _forward_to_elasticsearch(self, events: List[SIEMEvent]) -> bool:
        """Forward events to Elasticsearch via bulk API."""
        try:
            import aiohttp

            if not self._es_config.get("hosts"):
                return False

            host = self._es_config["hosts"][0]
            index_name = f"{self._es_config['index_prefix']}-{datetime.utcnow().strftime('%Y.%m.%d')}"

            # Build bulk payload
            lines = []
            for event in events:
                doc = event.to_elasticsearch()
                action = {"index": {"_index": index_name}}
                lines.append(json.dumps(action))
                lines.append(json.dumps(doc))
            bulk_body = "\n".join(lines) + "\n"

            headers = {"Content-Type": "application/x-ndjson"}
            if self._es_config.get("api_key"):
                headers["Authorization"] = f"ApiKey {self._es_config['api_key']}"
            elif self._es_config.get("username"):
                import base64
                auth = f"{self._es_config['username']}:{self._es_config.get('password', '')}"
                headers["Authorization"] = f"Basic {base64.b64encode(auth.encode()).decode()}"

            bulk_url = f"{host.rstrip('/')}/_bulk"

            async with aiohttp.ClientSession() as session:
                async with session.post(bulk_url, data=bulk_body, headers=headers, timeout=30) as resp:
                    if resp.status not in (200, 201):
                        text = await resp.text()
                        logger.warning(f"Elasticsearch bulk error: {resp.status} {text[:200]}")
                        return False
                    result = await resp.json()
                    if result.get("errors"):
                        logger.warning("Elasticsearch bulk had errors")
                        return False

            logger.debug(f"Forwarded {len(events)} events to Elasticsearch")
            return True

        except ImportError:
            logger.warning("aiohttp not installed — can't forward to Elasticsearch")
            return False
        except Exception as e:
            logger.error(f"Elasticsearch forwarding failed: {e}")
            self._failed_count += len(events)
            return False

    def _write_log_file(self, events: List[SIEMEvent]):
        """Write events to JSON log file for Logstash/Filebeat."""
        try:
            with open(self._log_file, "a") as f:
                for event in events:
                    f.write(event.to_json_log() + "\n")
        except Exception as e:
            logger.error(f"Failed to write SIEM log file: {e}")

    def _write_cef_log(self, events: List[SIEMEvent]):
        """Write events to CEF log file for legacy SIEM."""
        try:
            with open("logs/sentinel_cef.log", "a") as f:
                for event in events:
                    f.write(event.to_cef() + "\n")
        except Exception as e:
            logger.error(f"Failed to write CEF log: {e}")

    # ── Stats ──

    def get_stats(self) -> Dict[str, Any]:
        """Get SIEM forwarder statistics."""
        return {
            "forwarded": self._forwarded_count,
            "failed": self._failed_count,
            "buffered": len(self._event_buffer),
            "splunk_configured": bool(self._splunk_config),
            "elasticsearch_configured": bool(self._es_config),
            "log_file_configured": bool(self._log_file),
            "cef_enabled": self._cef_enabled,
        }


# ── Convenience: Create events from orchestrator results ──

def findings_to_siem_events(result: Dict) -> List[SIEMEvent]:
    """Convert an orchestrator analysis result to SIEM events.

    Args:
        result: Orchestrator.process() result dict

    Returns:
        List of SIEMEvent objects
    """
    siem = SIEMForwarder()
    events = []

    for finding in result.get("findings", []):
        event = siem.create_event(
            title=finding.get("title", "Security Finding"),
            description=finding.get("description", ""),
            severity=finding.get("severity", "MEDIUM"),
            source=finding.get("agent", "scanner"),
            category=finding.get("category", "vulnerability"),
            raw_data=finding,
            tags=finding.get("tags", []) + ["sentinel-analysis"],
            cwe_id=finding.get("cwe"),
            mitre_technique=finding.get("mitre_technique"),
        )
        events.append(event)

    return events


# ── Agent results formatter ──

def agent_result_to_siem_event(agent_result: Dict) -> SIEMEvent:
    """Convert a single agent result to a SIEM event.

    Args:
        agent_result: Individual agent result dict

    Returns:
        SIEMEvent instance
    """
    siem = SIEMForwarder()
    return siem.create_event(
        title=f"Agent Analysis: {agent_result.get('agent_name', 'unknown')}",
        description=agent_result.get("summary", "")[:500],
        severity="HIGH" if agent_result.get("confidence", 0) > 0.8 else "MEDIUM",
        source=agent_result.get("agent_name", "unknown"),
        category="agent_analysis",
        raw_data=agent_result,
        tags=["agent-result", "sentinel"],
    )
