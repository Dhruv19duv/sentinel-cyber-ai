"""
GitHub Webhook Integration — Auto-scan repositories on push events.

Features:
- Receives GitHub push/webhook events
- Auto-scans changed files for vulnerabilities
- Posts results back as commit status checks
- Sends alerts via MonitoringSystem for critical findings
- Manages webhook secrets and verification
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of scanning a repository push event."""
    repo: str
    branch: str
    commit_sha: str
    commit_message: str
    author: str
    files_changed: List[str]
    files_scanned: int
    findings: List[Dict]
    status: str
    scan_duration_ms: float
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return {
            "repo": self.repo,
            "branch": self.branch,
            "commit": self.commit_sha[:8],
            "author": self.author,
            "files_changed": len(self.files_changed),
            "files_scanned": self.files_scanned,
            "findings": len(self.findings),
            "status": self.status,
            "duration_ms": f"{self.scan_duration_ms:.0f}",
        }


class GitHubWebhookHandler:
    """Handles GitHub webhook events for auto-scanning.

    Processes push events, scans changed files, and posts
    commit status checks with results.
    """

    def __init__(self, webhook_secret: Optional[str] = None):
        self.webhook_secret = webhook_secret or os.environ.get("GITHUB_WEBHOOK_SECRET")
        self._orchestrator = None
        self._monitoring = None
        self._github_token = os.environ.get("GITHUB_TOKEN", "")
        self._scan_results: List[ScanResult] = []
        self._pending_scans: Dict[str, asyncio.Task] = {}
        self._event_handlers: Dict[str, List[Callable]] = {
            "push": [],
            "pull_request": [],
            "issues": [],
            "create": [],
            "delete": [],
        }

    def set_orchestrator(self, orchestrator):
        """Set the orchestrator instance for scanning."""
        self._orchestrator = orchestrator

    def set_monitoring(self, monitoring):
        """Set the monitoring system for alerting."""
        self._monitoring = monitoring

    def on(self, event: str, handler: Callable):
        """Register a handler for a GitHub event type.

        Args:
            event: GitHub event type (push, pull_request, issues, etc.)
            handler: Async callback function(event, payload)
        """
        if event in self._event_handlers:
            self._event_handlers[event].append(handler)
        else:
            self._event_handlers[event] = [handler]

    def verify_signature(self, signature: str, body: bytes) -> bool:
        """Verify GitHub webhook signature.

        Args:
            signature: X-Hub-Signature-256 header value
            body: Raw request body

        Returns:
            True if signature is valid
        """
        if not self.webhook_secret:
            logger.warning("No webhook secret configured — skipping verification")
            return True

        expected = "sha256=" + hmac.new(
            self.webhook_secret.encode(),
            body,
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected, signature)

    async def handle_webhook(self, event: str, payload: Dict, headers: Dict) -> Dict:
        """Handle an incoming GitHub webhook event.

        Args:
            event: GitHub event type (from X-GitHub-Event header)
            payload: Parsed webhook payload
            headers: Request headers

        Returns:
            Response dict
        """
        logger.info(f"Received GitHub webhook: {event}")

        # Dispatch to event handlers
        if event in self._event_handlers:
            for handler in self._event_handlers[event]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event, payload)
                    else:
                        handler(event, payload)
                except Exception as e:
                    logger.error(f"Event handler failed: {e}")

        # Auto-scan push events
        if event == "push":
            result = await self._handle_push(payload)
            return {"status": "ok", "scan": result.to_dict() if result else None}

        if event == "pull_request":
            result = await self._handle_pull_request(payload)
            return {"status": "ok", "scan": result.to_dict() if result else None}

        return {"status": "ok", "event": event}

    async def _handle_push(self, payload: Dict) -> Optional[ScanResult]:
        """Handle a push event — scan changed files.

        Args:
            payload: GitHub push event payload

        Returns:
            ScanResult if files were scanned
        """
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        ref = payload.get("ref", "")
        branch = ref.replace("refs/heads/", "")
        commits = payload.get("commits", [])

        if not commits:
            logger.info(f"No commits in push to {repo_name}")
            return None

        # Collect all changed files
        all_files = set()
        for commit in commits:
            for f in commit.get("added", []):
                all_files.add(f)
            for f in commit.get("modified", []):
                all_files.add(f)

        head_commit = commits[-1]
        commit_sha = head_commit.get("id", "")
        commit_message = head_commit.get("message", "")
        author = head_commit.get("author", {}).get("name", "unknown")

        if not all_files:
            logger.info(f"No changed files in push to {repo_name}:{branch}")
            return None

        logger.info(f"Scanning {len(all_files)} changed files in {repo_name}:{branch}")

        # Filter to supported source files
        supported_extensions = {'.py', '.js', '.ts', '.java', '.go', '.rs',
                                '.cpp', '.c', '.php', '.rb', '.sh', '.yaml', '.yml', '.json'}
        source_files = [f for f in all_files if any(f.endswith(ext) for ext in supported_extensions)]

        if not source_files:
            logger.info(f"No source files to scan in push to {repo_name}")
            return None

        # Scan the files
        start_time = time.time()
        findings = []

        if self._orchestrator:
            batch_size = 5
            for i in range(0, len(source_files), batch_size):
                batch = source_files[i:i + batch_size]
                for filepath in batch:
                    try:
                        query = (
                            f"Analyze this code change for vulnerabilities. "
                            f"Repository: {repo_name}, File: {filepath}\n"
                            f"Commit: {commit_sha[:8]} - {commit_message[:100]}"
                        )
                        result = await self._orchestrator.process(query)
                        file_findings = result.get("findings", [])
                        for f in file_findings:
                            f["file"] = filepath
                            f["repo"] = repo_name
                        findings.extend(file_findings)
                    except Exception as e:
                        logger.error(f"Scan failed for {filepath}: {e}")

        scan_duration = (time.time() - start_time) * 1000

        # Create scan result
        scan_result = ScanResult(
            repo=repo_name,
            branch=branch,
            commit_sha=commit_sha,
            commit_message=commit_message,
            author=author,
            files_changed=list(all_files),
            files_scanned=len(source_files),
            findings=findings,
            status="clean" if not findings else "vulnerabilities_found",
            scan_duration_ms=scan_duration,
        )

        self._scan_results.append(scan_result)

        # Send alert for critical findings
        if findings and self._monitoring:
            critical = [f for f in findings if f.get("severity") == "CRITICAL"]
            high = [f for f in findings if f.get("severity") == "HIGH"]

            if critical:
                await self._monitoring.send_alert(
                    title=f"Critical vulns found in {repo_name}",
                    message=f"Found {len(critical)} critical, {len(high)} high severity issues "
                            f"in push by {author} to {branch}",
                    severity=self._monitoring.AlertSeverity.CRITICAL,
                    source="github-webhook",
                    channel=self._monitoring.AlertChannel.WEBHOOK,
                    metadata={"repo": repo_name, "branch": branch, "commit": commit_sha[:8]},
                )

            # Track active threats
            for finding in critical[:5]:
                self._monitoring.track_threat(
                    description=finding.get("description", "Unknown vulnerability")[:200],
                    severity=self._monitoring.AlertSeverity.CRITICAL,
                    source_agent=finding.get("agent", "scanner"),
                    affected_files=[finding.get("file", "unknown")],
                    confidence=finding.get("confidence", 0.8),
                )

        # Post commit status check
        if self._github_token:
            await self._post_commit_status(repo_name, commit_sha, scan_result)

        logger.info(
            f"Scan complete: {repo_name}@{branch[:20]} — "
            f"{len(source_files)} files, {len(findings)} findings in {scan_duration:.0f}ms"
        )

        return scan_result

    async def _handle_pull_request(self, payload: Dict) -> Optional[ScanResult]:
        """Handle a pull request event — scan changed files."""
        action = payload.get("action", "")
        if action not in ("opened", "synchronize"):
            return None

        pr = payload.get("pull_request", {})
        repo_name = payload.get("repository", {}).get("full_name", "unknown")
        head_sha = pr.get("head", {}).get("sha", "")
        title = pr.get("title", "")
        author = pr.get("user", {}).get("login", "unknown")

        logger.info(f"PR {action}: {repo_name}#{pr.get('number')} — {title}")

        # For PRs, we'd need to fetch the diff via GitHub API
        # For now, create a placeholder scan result
        scan_result = ScanResult(
            repo=repo_name,
            branch=pr.get("head", {}).get("ref", "unknown"),
            commit_sha=head_sha,
            commit_message=f"PR: {title}",
            author=author,
            files_changed=[],
            files_scanned=0,
            findings=[],
            status="pending_api_scan",
            scan_duration_ms=0,
        )

        return scan_result

    async def _post_commit_status(self, repo: str, sha: str, result: ScanResult):
        """Post a commit status check to GitHub.

        Args:
            repo: Repository full name (user/repo)
            sha: Commit SHA
            result: Scan result
        """
        try:
            import aiohttp

            finding_count = len(result.findings)
            state = "success" if finding_count == 0 else "failure"
            description = (
                f"No vulnerabilities found" if finding_count == 0
                else f"Found {finding_count} issue(s)"
            )

            url = f"https://api.github.com/repos/{repo}/statuses/{sha}"
            payload = {
                "state": state,
                "description": description,
                "context": "sentinel/security-scan",
                "target_url": "https://sentinel-ai.dev",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {self._github_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                ) as resp:
                    if resp.status not in (200, 201):
                        text = await resp.text()
                        logger.warning(f"Failed to post commit status: {resp.status}")
                    else:
                        logger.info(f"Posted commit status: {state} for {sha[:8]}")

        except ImportError:
            logger.warning("aiohttp not installed for commit status posting")
        except Exception as e:
            logger.error(f"Failed to post commit status: {e}")

    def get_recent_scans(self, limit: int = 20) -> List[Dict]:
        """Get recent scan results.

        Args:
            limit: Maximum number of results

        Returns:
            List of scan result dicts
        """
        return [r.to_dict() for r in self._scan_results[-limit:]]

    def get_stats(self) -> Dict[str, Any]:
        """Get webhook handler statistics.

        Returns:
            Dict with scan statistics
        """
        total = len(self._scan_results)
        clean = sum(1 for r in self._scan_results if r.status == "clean")
        vulnerable = sum(1 for r in self._scan_results if r.status == "vulnerabilities_found")

        return {
            "total_scans": total,
            "clean_scans": clean,
            "vulnerable_scans": vulnerable,
            "total_files_scanned": sum(r.files_scanned for r in self._scan_results),
            "total_findings": sum(len(r.findings) for r in self._scan_results),
            "webhook_configured": bool(self.webhook_secret),
            "github_token_configured": bool(self._github_token),
            "orchestrator_connected": self._orchestrator is not None,
            "monitoring_connected": self._monitoring is not None,
            "pending_scans": len(self._pending_scans),
        }


def setup_github_routes(router, orchestrator, monitoring=None):
    """Add GitHub webhook endpoints to the FastAPI router.

    Args:
        router: FastAPI APIRouter
        orchestrator: The Sentinel orchestrator instance
        monitoring: Optional monitoring system for alerts
    """
    from fastapi import Request, HTTPException

    handler = GitHubWebhookHandler()
    handler.set_orchestrator(orchestrator)
    if monitoring:
        handler.set_monitoring(monitoring)

    @router.post("/github/webhook")
    async def github_webhook(request: Request):
        """Handle incoming GitHub webhook events."""
        body = await request.body()
        signature = request.headers.get("X-Hub-Signature-256", "")
        event = request.headers.get("X-GitHub-Event", "push")
        delivery = request.headers.get("X-GitHub-Delivery", "")

        # Verify signature
        if not handler.verify_signature(signature, body):
            raise HTTPException(status_code=403, detail="Invalid signature")

        payload = json.loads(body)
        result = await handler.handle_webhook(event, payload, dict(request.headers))
        return result

    @router.get("/github/stats")
    async def github_stats():
        """Get GitHub webhook statistics."""
        return handler.get_stats()

    @router.get("/github/scans")
    async def github_scans(limit: int = 20):
        """Get recent scan results."""
        return {"scans": handler.get_recent_scans(limit)}

    return router
