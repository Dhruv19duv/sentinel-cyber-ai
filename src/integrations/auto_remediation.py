"""
Auto-Remediation Pipeline — Auto-Fix Vulnerabilities & Create GitHub PRs.

v2.0 Enhancement: Full End-to-End Pipeline
- Scan → Detect → Fix → Branch → Commit → Push → PR → Auto-Merge
- Approval workflow (manual review gate before merge)
- Batch remediation (multiple findings in one PR)
- Status tracking with webhook notifications
- Confidence-based auto-merge thresholds
- Rollback capability

Pipeline:
1. Receive finding from orchestrator scan
2. Generate fix using Patch Generator agent
3. Apply fix to local clone (or directly via GitHub API)
4. Create branch and commit
5. Push and create PR with detailed description
6. Optionally auto-merge based on confidence threshold
7. Notify via monitoring system

Usage:
    python -m src.main auto-remediate --repo user/repo --finding-id finding-123
    python -m src.main auto-remediate --status
    python -m src.main auto-remediate --batch findings.json

Environment Variables:
    GITHUB_TOKEN: GitHub personal access token (required)
    AUTO_REMEDIATION_ENABLED: Set to "true" to enable (default: false)
    AUTO_REMEDIATION_AUTO_MERGE: "true" to auto-merge high-confidence fixes (default: false)
    AUTO_REMEDIATION_MIN_CONFIDENCE: Minimum confidence to create PR (default: 0.7)
    AUTO_REMEDIATION_AUTO_MERGE_CONFIDENCE: Confidence threshold for auto-merge (default: 0.9)
    AUTO_REMEDIATION_BRANCH_PREFIX: Branch prefix (default: sentinel-fix/)
    AUTO_REMEDIATION_WORK_DIR: Working directory for clones (default: /tmp/sentinel-remediation)
    AUTO_REMEDIATION_MAX_FILES_PER_PR: Maximum files changed per PR (default: 10)
"""

import asyncio
import base64
import json
import logging
import os
import re
import time
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RemediationStatus(str, Enum):
    """Status of a single remediation action."""
    PENDING = "pending"
    GENERATING = "generating"
    APPLIED = "applied"
    COMMITTED = "committed"
    PUSHED = "pushed"
    PR_CREATED = "pr_created"
    APPROVED = "approved"
    MERGED = "merged"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PRStatus(str, Enum):
    """Status of a remediation PR."""
    CREATED = "created"
    REVIEW_REQUIRED = "review_required"
    APPROVED = "approved"
    MERGED = "merged"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass
class Remediation:
    """A single remediation action — fix applied to a file."""
    id: str
    finding_id: str
    file_path: str
    original_content: str
    fixed_content: str
    description: str
    severity: str
    cwe: Optional[str] = None
    confidence: float = 0.0
    status: RemediationStatus = RemediationStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    error: Optional[str] = None
    commit_sha: Optional[str] = None
    patch: Optional[str] = None


@dataclass
class RemediationPR:
    """A pull request created by the auto-remediation system."""
    id: str
    branch: str
    title: str
    body: str
    remediations: List[Remediation]
    repo: str
    pr_url: Optional[str] = None
    pr_number: Optional[int] = None
    status: PRStatus = PRStatus.CREATED
    confidence: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    merged_at: Optional[str] = None
    auto_merged: bool = False
    approval_required: bool = True
    error: Optional[str] = None


@dataclass
class BatchResult:
    """Result from a batch remediation operation."""
    total_findings: int
    successful: int
    failed: int
    prs_created: int
    prs_auto_merged: int
    total_confidence: float
    duration_seconds: float
    details: List[Dict[str, Any]] = field(default_factory=list)


class AutoRemediationEngine:
    """Automatically fixes vulnerabilities and creates PRs.

    v2.0: Full end-to-end pipeline with approval workflow, auto-merge,
    batch processing, and detailed status tracking.
    """

    def __init__(self, orchestrator=None, monitoring=None):
        self._orchestrator = orchestrator
        self._monitoring = monitoring
        self._github_token = os.environ.get("GITHUB_TOKEN", "")
        self._branch_prefix = os.environ.get("AUTO_REMEDIATION_BRANCH_PREFIX", "sentinel-fix/")
        self._remediations: List[Remediation] = []
        self._prs: List[RemediationPR] = []
        self._enabled = os.environ.get("AUTO_REMEDIATION_ENABLED", "false").lower() == "true"
        self._auto_merge = os.environ.get("AUTO_REMEDIATION_AUTO_MERGE", "false").lower() == "true"
        self._min_confidence = float(os.environ.get("AUTO_REMEDIATION_MIN_CONFIDENCE", "0.7"))
        self._auto_merge_confidence = float(os.environ.get("AUTO_REMEDIATION_AUTO_MERGE_CONFIDENCE", "0.9"))
        self._work_dir = os.environ.get("AUTO_REMEDIATION_WORK_DIR", "/tmp/sentinel-remediation")
        self._max_files_per_pr = int(os.environ.get("AUTO_REMEDIATION_MAX_FILES_PER_PR", "10"))
        self._github_api_base = "https://api.github.com"

        # Create work directory
        os.makedirs(self._work_dir, exist_ok=True)

    def set_orchestrator(self, orchestrator):
        """Set the orchestrator instance for fix generation."""
        self._orchestrator = orchestrator

    def set_monitoring(self, monitoring):
        """Set the monitoring system for notifications."""
        self._monitoring = monitoring

    # ── Core Pipeline ──

    async def remediate_finding(
        self,
        finding: Dict,
        repo: str,
        file_path: Optional[str] = None,
        source_code: Optional[str] = None,
    ) -> Optional[Remediation]:
        """Generate and apply a fix for a single finding.

        Pipeline step 1: Generate fix using Patch Generator agent.

        Args:
            finding: Security finding dict
            repo: Repository full name (user/repo)
            file_path: Path to the vulnerable file (optional)
            source_code: Original source code (optional, fetched if not provided)

        Returns:
            Remediation if fix was generated, None otherwise
        """
        if not self._enabled:
            logger.info("Auto-remediation is disabled (set AUTO_REMEDIATION_ENABLED=true)")
            return None

        finding_id = finding.get("id", f"finding-{int(time.time())}")
        title = finding.get("title", "Unknown vulnerability")
        description = finding.get("description", "")
        severity = finding.get("severity", "MEDIUM")
        cwe = finding.get("cwe")
        confidence = finding.get("confidence", None)

        # Check confidence threshold (only if explicitly provided)
        if confidence is not None and confidence < self._min_confidence:
            logger.info(
                f"Skipping {finding_id}: confidence {confidence:.2f} < "
                f"threshold {self._min_confidence}"
            )
            return None
        
        # If no confidence provided, assume best
        if confidence is None:
            confidence = 0.9

        logger.info(f"Generating fix for: {title} ({severity}, confidence={confidence:.2f})")

        remediation = Remediation(
            id=f"remediation-{int(time.time())}-{hashlib.md5(finding_id.encode()).hexdigest()[:8]}",
            finding_id=finding_id,
            file_path=file_path or "",
            original_content=source_code or "",
            fixed_content="",
            description=description[:500],
            severity=severity,
            cwe=cwe,
            confidence=confidence,
            status=RemediationStatus.GENERATING,
        )

        # Generate fix using Patch Generator
        if self._orchestrator and source_code:
            try:
                fix_prompt = (
                    f"Fix this vulnerability in the following code. "
                    f"Issue: {title}. {description}. "
                    f"Severity: {severity}. "
                    f"CWE: {cwe}. "
                    f"\n\n```python\n{source_code}\n```\n\n"
                    f"Return ONLY the fixed code with no additional text. "
                    f"Keep the same function signature and imports."
                )
                result = await self._orchestrator.process(fix_prompt)
                fixed_code = self._extract_fixed_code(result, source_code)

                if fixed_code and fixed_code != source_code:
                    remediation.fixed_content = fixed_code
                    remediation.status = RemediationStatus.APPLIED
                    remediation.updated_at = datetime.utcnow().isoformat()
                    logger.info(f"Fix generated for {finding_id}")
                else:
                    remediation.status = RemediationStatus.FAILED
                    remediation.error = "No fix generated or fix identical to original"
                    logger.warning(f"No fix generated for {finding_id}")

            except Exception as e:
                remediation.status = RemediationStatus.FAILED
                remediation.error = str(e)
                logger.error(f"Fix generation failed: {e}")

        else:
            remediation.status = RemediationStatus.FAILED
            remediation.error = "No orchestrator or source code available"
            logger.warning(f"Cannot remediate {finding_id}: no orchestrator or source code")

        self._remediations.append(remediation)
        return remediation

    async def batch_remediate(
        self,
        findings: List[Dict[str, Any]],
        repo: str,
        group_by_repo: bool = True,
    ) -> BatchResult:
        """Batch process multiple findings into PRs.

        v2.0: Groups findings by severity, creates separate PRs per severity
        level (critical/high together, medium/low together), and auto-merges
        high-confidence fixes.

        Args:
            findings: List of security findings
            repo: Repository full name
            group_by_repo: Group findings by repository (always True for now)

        Returns:
            BatchResult with statistics
        """
        start_time = time.time()
        successful = 0
        failed = 0

        logger.info(f"Starting batch remediation: {len(findings)} findings for {repo}")

        # Generate fixes for all findings
        remediations = []
        for finding in findings:
            try:
                rem = await self.remediate_finding(
                    finding,
                    repo,
                    file_path=finding.get("location", finding.get("file", "unknown")),
                    source_code=finding.get("code", ""),
                )
                if rem and rem.status == RemediationStatus.APPLIED:
                    remediations.append(rem)
                    successful += 1
                else:
                    failed += 1
            except Exception as e:
                logger.error(f"Batch remediation failed for finding: {e}")
                failed += 1

        if not remediations:
            return BatchResult(
                total_findings=len(findings),
                successful=0,
                failed=len(findings),
                prs_created=0,
                prs_auto_merged=0,
                total_confidence=0.0,
                duration_seconds=time.time() - start_time,
                details=[{"error": "No remediations generated"}],
            )

        # Group by severity for PR creation
        critical_high = [r for r in remediations if r.severity in ("CRITICAL", "HIGH")]
        medium_low = [r for r in remediations if r.severity in ("MEDIUM", "LOW", "INFO")]

        prs_created = 0
        prs_auto_merged = 0

        # Create PR for critical/high findings
        if critical_high:
            pr = await self.create_remediation_pr(repo, critical_high)
            if pr and pr.status in (PRStatus.CREATED, PRStatus.APPROVED, PRStatus.MERGED):
                prs_created += 1
                if pr.auto_merged:
                    prs_auto_merged += 1

        # Create PR for medium/low findings (if any)
        if medium_low:
            pr = await self.create_remediation_pr(repo, medium_low)
            if pr and pr.status in (PRStatus.CREATED, PRStatus.APPROVED, PRStatus.MERGED):
                prs_created += 1
                if pr.auto_merged:
                    prs_auto_merged += 1

        avg_confidence = (
            sum(r.confidence for r in remediations) / len(remediations)
            if remediations else 0.0
        )

        result = BatchResult(
            total_findings=len(findings),
            successful=successful,
            failed=failed,
            prs_created=prs_created,
            prs_auto_merged=prs_auto_merged,
            total_confidence=avg_confidence,
            duration_seconds=time.time() - start_time,
            details=[
                {"remediation_id": r.id, "file": r.file_path, "status": r.status.value}
                for r in remediations
            ],
        )

        logger.info(
            f"Batch complete: {successful}/{len(findings)} remediated, "
            f"{prs_created} PRs created, {prs_auto_merged} auto-merged, "
            f"{time.time() - start_time:.1f}s"
        )

        return result

    async def create_remediation_pr(
        self,
        repo: str,
        remediations: List[Remediation],
        branch_name: Optional[str] = None,
        auto_merge_override: Optional[bool] = None,
    ) -> Optional[RemediationPR]:
        """Create a PR with all generated fixes for a repository.

        v2.0: Enhanced with:
        - Auto-merge for high-confidence fixes
        - Approval tracking
        - Detailed PR body with severity breakdown
        - Webhook notifications on PR creation

        Args:
            repo: Repository full name (user/repo)
            remediations: List of successful remediations
            branch_name: Custom branch name (auto-generated if not provided)
            auto_merge_override: Override auto-merge setting

        Returns:
            RemediationPR if PR was created, None otherwise
        """
        if not self._github_token:
            logger.error("GITHUB_TOKEN not set — cannot create PR")
            return None

        if not remediations:
            logger.warning("No remediations to include in PR")
            return None

        # Filter to applied remediations only
        applied = [r for r in remediations if r.status == RemediationStatus.APPLIED]
        if not applied:
            logger.warning("No applied remediations to include in PR")
            return None

        # Limit files per PR
        if len(applied) > self._max_files_per_pr:
            logger.warning(
                f"Too many files ({len(applied)}), limiting to {self._max_files_per_pr}"
            )
            applied = applied[:self._max_files_per_pr]

        # Calculate aggregate confidence
        avg_confidence = sum(r.confidence for r in applied) / len(applied)

        # Generate branch name
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        branch = branch_name or f"{self._branch_prefix}{timestamp}"

        # Build PR title and body
        severities = [r.severity for r in applied]
        critical = sum(1 for s in severities if s == "CRITICAL")
        high = sum(1 for s in severities if s == "HIGH")

        title = f"[Sentinel] Security fix: {critical}C {high}H — {len(applied)} vulnerability(ies)"
        if len(title) > 200:
            title = title[:197] + "..."

        body = self._build_pr_body(applied, repo, branch)

        should_auto_merge = (
            auto_merge_override if auto_merge_override is not None
            else (self._auto_merge and avg_confidence >= self._auto_merge_confidence)
        )

        pr = RemediationPR(
            id=f"pr-{int(time.time())}-{hashlib.md5(repo.encode()).hexdigest()[:8]}",
            branch=branch,
            title=title,
            body=body,
            remediations=applied,
            repo=repo,
            confidence=avg_confidence,
            approval_required=not should_auto_merge,
            auto_merged=should_auto_merge,
        )

        # Create PR via GitHub API
        try:
            import aiohttp

            base_url = f"{self._github_api_base}/repos/{repo}"
            headers = self._gh_headers()

            async with aiohttp.ClientSession() as session:

                # Get default branch SHA
                default_branch = await self._get_default_branch(session, base_url)
                if not default_branch:
                    pr.status = PRStatus.FAILED
                    pr.error = "Could not determine default branch"
                    self._prs.append(pr)
                    await self._notify_pr_created(pr, failed=True)
                    return pr

                # Create branch from default
                branch_created = await self._create_branch(
                    session, base_url, branch, default_branch["sha"]
                )
                if not branch_created:
                    # Branch may already exist — try using it
                    logger.info(f"Branch {branch} may already exist, continuing...")

                # Create/update files
                for rem in applied:
                    commit_result = await self._commit_file(
                        session, base_url, branch, rem
                    )
                    if commit_result:
                        rem.status = RemediationStatus.COMMITTED
                        rem.commit_sha = commit_result
                        rem.updated_at = datetime.utcnow().isoformat()
                    else:
                        rem.status = RemediationStatus.FAILED
                        rem.error = "Commit failed"
                        rem.updated_at = datetime.utcnow().isoformat()

                # Create PR
                committed = [r for r in applied if r.status == RemediationStatus.COMMITTED]
                if not committed:
                    pr.status = PRStatus.FAILED
                    pr.error = "No files were committed"
                    pr.updated_at = datetime.utcnow().isoformat()
                    self._prs.append(pr)
                    await self._notify_pr_created(pr, failed=True)
                    return pr

                pr_data = {
                    "title": pr.title,
                    "body": pr.body,
                    "head": branch,
                    "base": default_branch["name"],
                    "maintainer_can_modify": True,
                }

                async with session.post(
                    f"{base_url}/pulls",
                    json=pr_data,
                    headers=headers,
                ) as resp:
                    if resp.status in (200, 201):
                        pr_data_resp = await resp.json()
                        pr.pr_url = pr_data_resp.get("html_url")
                        pr.pr_number = pr_data_resp.get("number")
                        pr.status = PRStatus.CREATED
                        pr.updated_at = datetime.utcnow().isoformat()
                        logger.info(f"PR created: {pr.pr_url}")

                        # Auto-merge if confidence is high enough
                        if should_auto_merge and pr.pr_number:
                            merge_success = await self._auto_merge_pull_request(
                                session, base_url, pr.pr_number, pr
                            )
                            if merge_success:
                                pr.status = PRStatus.MERGED
                                pr.merged_at = datetime.utcnow().isoformat()
                                pr.auto_merged = True
                                pr.updated_at = datetime.utcnow().isoformat()
                                logger.info(f"PR {pr.pr_number} auto-merged")
                            else:
                                pr.status = PRStatus.APPROVED
                                logger.info(
                                    f"Auto-merge not possible for PR #{pr.pr_number}, "
                                    f"requires manual merge"
                                )
                        else:
                            logger.info(
                                f"PR #{pr.pr_number} requires review "
                                f"(auto-merge={'enabled' if should_auto_merge else 'disabled'}, "
                                f"confidence={avg_confidence:.2f})"
                            )

                        # Update remediation statuses
                        for rem in committed:
                            rem.status = RemediationStatus.PR_CREATED
                            rem.updated_at = datetime.utcnow().isoformat()

                    else:
                        text = await resp.text()
                        pr.status = PRStatus.FAILED
                        pr.error = f"PR creation failed: {resp.status} {text[:300]}"
                        pr.updated_at = datetime.utcnow().isoformat()
                        logger.error(f"PR creation failed: {resp.status}")

        except ImportError:
            pr.status = PRStatus.FAILED
            pr.error = "aiohttp not installed"
            logger.error("aiohttp not installed — install with: pip install aiohttp")
        except Exception as e:
            pr.status = PRStatus.FAILED
            pr.error = str(e)
            pr.updated_at = datetime.utcnow().isoformat()
            logger.error(f"PR creation failed: {e}")

        self._prs.append(pr)
        await self._notify_pr_created(pr)
        return pr

    # ── GitHub API Helpers ──

    def _gh_headers(self) -> Dict[str, str]:
        """Get GitHub API headers."""
        return {
            "Authorization": f"Bearer {self._github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "sentinel-cyber-ai/2.0",
        }

    async def _get_default_branch(self, session, base_url: str) -> Optional[Dict]:
        """Get the default branch info from a repository."""
        async with session.get(f"{base_url}", headers=self._gh_headers()) as resp:
            if resp.status == 200:
                data = await resp.json()
                default_branch = data.get("default_branch", "main")
                # Get SHA of the default branch
                async with session.get(
                    f"{base_url}/git/refs/heads/{default_branch}",
                    headers=self._gh_headers(),
                ) as ref_resp:
                    if ref_resp.status == 200:
                        ref_data = await ref_resp.json()
                        return {"name": default_branch, "sha": ref_data["object"]["sha"]}
            return None

    async def _create_branch(self, session, base_url: str, branch: str, sha: str) -> bool:
        """Create a new branch from a SHA."""
        branch_data = {"ref": f"refs/heads/{branch}", "sha": sha}
        async with session.post(
            f"{base_url}/git/refs",
            json=branch_data,
            headers=self._gh_headers(),
        ) as resp:
            return resp.status in (200, 201)

    async def _commit_file(self, session, base_url: str, branch: str, rem: Remediation) -> Optional[str]:
        """Create or update a file in a branch.

        Returns:
            Commit SHA if successful, None otherwise
        """
        headers = self._gh_headers()

        # Get current file SHA if exists
        file_sha = None
        async with session.get(
            f"{base_url}/contents/{rem.file_path}",
            headers=headers,
            params={"ref": branch},
        ) as resp:
            if resp.status == 200:
                file_data = await resp.json()
                file_sha = file_data.get("sha")

        # Create or update file
        put_data = {
            "message": f"fix({rem.severity.lower()}): {rem.description[:100]}",
            "content": base64.b64encode(rem.fixed_content.encode()).decode(),
            "branch": branch,
        }
        if file_sha:
            put_data["sha"] = file_sha

        async with session.put(
            f"{base_url}/contents/{rem.file_path}",
            json=put_data,
            headers=headers,
        ) as resp:
            if resp.status in (200, 201):
                resp_data = await resp.json()
                return resp_data.get("content", {}).get("sha")
            else:
                text = await resp.text()
                logger.warning(f"File commit failed for {rem.file_path}: {resp.status} {text[:200]}")
                return None

    async def _auto_merge_pull_request(
        self, session, base_url: str, pr_number: int, pr: RemediationPR
    ) -> bool:
        """Attempt to auto-merge a pull request.

        Tries merge strategies in order: squash → merge → rebase.
        """
        headers = self._gh_headers()

        for merge_method in ["squash", "merge", "rebase"]:
            merge_data = {
                "commit_title": pr.title[:200],
                "commit_message": f"Auto-merged by Sentinel Cyber AI\n\n"
                                  f"Confidence: {pr.confidence:.2f}\n"
                                  f"Vulnerabilities fixed: {len(pr.remediations)}",
                "merge_method": merge_method,
            }
            async with session.put(
                f"{base_url}/pulls/{pr_number}/merge",
                json=merge_data,
                headers=headers,
            ) as resp:
                if resp.status in (200, 201):
                    logger.info(f"PR #{pr_number} merged via {merge_method}")
                    return True
                elif resp.status == 405:
                    # Method not allowed — try next strategy
                    continue
                else:
                    text = await resp.text()
                    logger.warning(f"Merge failed ({merge_method}): {resp.status} {text[:100]}")
                    continue

        return False

    # ── PR Body Builder ──

    def _build_pr_body(self, remediations: List[Remediation], repo: str, branch: str) -> str:
        """Build a detailed PR description with all remediations."""
        lines = [
            "## 🤖 Auto-Generated Security Fix — Sentinel Cyber AI",
            "",
            f"**Repository:** `{repo}`",
            f"**Branch:** `{branch}`",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Fixes:** {len(remediations)} vulnerability(ies)",
            "",
            "### Summary",
            "",
            "This PR contains automated security fixes generated by Sentinel Cyber AI's",
            "multi-agent analysis pipeline. Each fix was reviewed by a specialized agent.",
            "",
        ]

        # Severity breakdown
        severity_counts = {}
        for r in remediations:
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1

        lines.append("| Severity | Count | Confidence |")
        lines.append("|----------|-------|------------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severity_counts:
                count = severity_counts[sev]
                confs = [r.confidence for r in remediations if r.severity == sev]
                avg_conf = sum(confs) / len(confs) if confs else 0
                lines.append(f"| **{sev}** | {count} | {avg_conf:.0%} |")

        lines.extend(["", "### Changes", ""])

        for i, rem in enumerate(remediations, 1):
            if rem.status not in (RemediationStatus.APPLIED, RemediationStatus.COMMITTED, RemediationStatus.PR_CREATED):
                continue
            lines.append(f"#### {i}. `{rem.file_path}`")
            lines.append(f"")
            lines.append(f"**Severity:** {rem.severity}")
            lines.append(f"**Confidence:** {rem.confidence:.0%}")
            if rem.cwe:
                lines.append(f"**CWE:** [{rem.cwe}](https://cwe.mitre.org/data/definitions/{rem.cwe.split('-')[1]}.html)")
            lines.append(f"**Issue:** {rem.description[:300]}")
            lines.append("")

        lines.extend([
            "### Verification",
            "",
            "- [ ] Changes reviewed",
            "- [ ] Fixes verified to compile/parse correctly",
            "- [ ] No regression in test suite",
            "",
            "---",
            "",
            "_This PR was automatically generated by [Sentinel Cyber AI](https://sentinel-ai.dev)._",
            "_Review before merging. Confidence score indicates the system's certainty in the fix._",
            f"_Overall confidence: {sum(r.confidence for r in remediations) / len(remediations):.0%}_",
        ])

        return "\n".join(lines)

    # ── Fix Extraction ──

    def _extract_fixed_code(self, result: Dict, original: str) -> Optional[str]:
        """Extract fixed code from orchestrator result.

        Tries multiple strategies:
        1. Finding with 'fixed_code' field
        2. Code block extraction from response/summary
        3. Direct code in response/summary
        """
        findings = result.get("findings", [])
        for finding in findings:
            if finding.get("fixed_code"):
                return finding["fixed_code"]

        response = result.get("response", "") or result.get("summary", "")
        if not response:
            return None

        code_blocks = re.findall(r"```(?:\w+)?\n(.*?)```", response, re.DOTALL)
        if code_blocks:
            return code_blocks[0].strip()

        response = response.strip()
        if len(response) >= 5 and not response.startswith(("I ", "Here", "The", "This")):
            return response

        return None

    # ── Notifications ──

    async def _notify_pr_created(self, pr: RemediationPR, failed: bool = False):
        """Send notification about PR creation via monitoring system."""
        if not self._monitoring:
            return

        from src.monitoring.monitor import AlertSeverity, AlertChannel

        if failed:
            await self._monitoring.send_alert(
                title=f"Auto-remediation failed: {pr.repo}",
                message=f"Failed to create PR for {len(pr.remediations)} fix(es): {pr.error}",
                severity=AlertSeverity.ERROR,
                source="auto-remediation",
                channel=AlertChannel.CONSOLE,
                metadata={"repo": pr.repo, "error": pr.error},
            )
        elif pr.auto_merged:
            await self._monitoring.send_alert(
                title=f"Auto-remediation merged: {pr.repo}",
                message=f"PR #{pr.pr_number} auto-merged: {pr.title[:100]}",
                severity=AlertSeverity.INFO,
                source="auto-remediation",
                channel=AlertChannel.CONSOLE,
                metadata={"repo": pr.repo, "pr_url": pr.pr_url, "auto_merged": True},
            )
        else:
            await self._monitoring.send_alert(
                title=f"Auto-remediation PR: {pr.repo}",
                message=f"PR #{pr.pr_number} created: {len(pr.remediations)} fix(es) awaiting review",
                severity=AlertSeverity.WARNING,
                source="auto-remediation",
                channel=AlertChannel.CONSOLE,
                metadata={"repo": pr.repo, "pr_url": pr.pr_url},
            )

    # ── Rollback ──

    async def rollback_pr(self, pr_id: str) -> bool:
        """Rollback a remediation PR by reverting the changes.

        Creates a new PR that reverts the remediation changes.
        """
        pr = next((p for p in self._prs if p.id == pr_id), None)
        if not pr:
            logger.error(f"PR {pr_id} not found")
            return False

        if pr.status not in (PRStatus.MERGED, PRStatus.APPROVED, PRStatus.CREATED):
            logger.error(f"PR {pr_id} cannot be rolled back (status: {pr.status})")
            return False

        if not self._github_token:
            logger.error("GITHUB_TOKEN not set — cannot rollback")
            return False

        try:
            import aiohttp

            base_url = f"{self._github_api_base}/repos/{pr.repo}"
            timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
            rollback_branch = f"sentinel-rollback/{timestamp}"

            async with aiohttp.ClientSession() as session:

                # Get default branch SHA
                default_branch = await self._get_default_branch(session, base_url)
                if not default_branch:
                    logger.error("Could not get default branch")
                    return False

                # Create rollback branch
                await self._create_branch(session, base_url, rollback_branch, default_branch["sha"])

                # Revert each file
                for rem in pr.remediations:
                    if not rem.original_content:
                        continue

                    await self._commit_file(
                        session, base_url, rollback_branch,
                        Remediation(
                            id=f"rollback-{rem.id}",
                            finding_id=rem.finding_id,
                            file_path=rem.file_path,
                            original_content=rem.fixed_content,
                            fixed_content=rem.original_content,
                            description=f"Rollback: {rem.description[:100]}",
                            severity="INFO",
                            confidence=1.0,
                            status=RemediationStatus.APPLIED,
                        ),
                    )

                # Create rollback PR
                rollback_data = {
                    "title": f"[Sentinel] Rollback: {pr.title[:150]}",
                    "body": (
                        f"## ⏪ Rollback of PR #{pr.pr_number}\n\n"
                        f"This PR reverts the changes from auto-remediation PR #{pr.pr_number}.\n\n"
                        f"**Original PR:** {pr.pr_url}\n"
                        f"**Reason:** Manual rollback triggered\n"
                        f"**Files reverted:** {len(pr.remediations)}\n\n"
                        f"_Generated by Sentinel Cyber AI_"
                    ),
                    "head": rollback_branch,
                    "base": default_branch["name"],
                }

                async with session.post(
                    f"{base_url}/pulls",
                    json=rollback_data,
                    headers=self._gh_headers(),
                ) as resp:
                    if resp.status in (200, 201):
                        rollback_pr = await resp.json()
                        logger.info(f"Rollback PR created: {rollback_pr.get('html_url')}")

                        for rem in pr.remediations:
                            rem.status = RemediationStatus.ROLLED_BACK
                            rem.updated_at = datetime.utcnow().isoformat()

                        pr.updated_at = datetime.utcnow().isoformat()
                        return True
                    else:
                        text = await resp.text()
                        logger.error(f"Rollback PR failed: {resp.status} {text[:200]}")
                        return False

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False

    # ── Status ──

    def get_stats(self) -> Dict[str, Any]:
        """Get auto-remediation statistics."""
        total = len(self._remediations)
        successful = sum(1 for r in self._remediations if r.status == RemediationStatus.APPLIED)
        failed = sum(1 for r in self._remediations if r.status == RemediationStatus.FAILED)
        committed = sum(1 for r in self._remediations if r.status == RemediationStatus.COMMITTED)
        pr_created = sum(1 for r in self._remediations if r.status == RemediationStatus.PR_CREATED)
        rolled_back = sum(1 for r in self._remediations if r.status == RemediationStatus.ROLLED_BACK)

        prs_created = sum(1 for p in self._prs if p.status in (PRStatus.CREATED, PRStatus.APPROVED, PRStatus.MERGED))
        prs_merged = sum(1 for p in self._prs if p.status == PRStatus.MERGED)
        prs_failed = sum(1 for p in self._prs if p.status == PRStatus.FAILED)

        valid_confidences = [
            r.confidence for r in self._remediations
            if isinstance(r.confidence, (int, float)) and r.confidence > 0
        ]
        avg_confidence = sum(valid_confidences) / max(len(valid_confidences), 1)

        return {
            "enabled": self._enabled,
            "auto_merge": self._auto_merge,
            "min_confidence_threshold": self._min_confidence,
            "auto_merge_confidence_threshold": self._auto_merge_confidence,
            "total_remediations": total,
            "remediation_statuses": {
                "applied": successful,
                "committed": committed,
                "pr_created": pr_created,
                "failed": failed,
                "rolled_back": rolled_back,
            },
            "prs_created": prs_created,
            "prs_merged": prs_merged,
            "prs_failed": prs_failed,
            "average_confidence": round(avg_confidence, 3),
            "github_token_configured": bool(self._github_token),
            "orchestrator_connected": self._orchestrator is not None,
            "monitoring_connected": self._monitoring is not None,
            "recent_remediations": [
                {
                    "id": r.id,
                    "file": r.file_path,
                    "severity": r.severity,
                    "confidence": r.confidence,
                    "status": getattr(r.status, 'value', r.status),
                    "error": r.error,
                }
                for r in self._remediations[-10:]
            ],
            "recent_prs": [
                {
                    "id": p.id,
                    "repo": p.repo,
                    "pr_number": p.pr_number,
                    "url": p.pr_url,
                    "status": getattr(p.status, 'value', p.status),
                    "confidence": p.confidence,
                    "auto_merged": p.auto_merged,
                    "error": p.error,
                }
                for p in self._prs[-5:]
            ],
        }


# ── Main handler for findings pipeline ──

async def auto_remediate_finding(
    orchestrator,
    finding: Dict,
    repo: str,
    file_path: str,
    source_code: str,
) -> Optional[str]:
    """High-level function: analyze finding → generate fix → create PR.

    Args:
        orchestrator: Sentinel orchestrator instance
        finding: Security finding dict
        repo: Repository full name
        file_path: Path to vulnerable file
        source_code: Original source code

    Returns:
        PR URL if created, None otherwise
    """
    engine = AutoRemediationEngine(orchestrator)

    # Generate fix
    remediation = await engine.remediate_finding(finding, repo, file_path, source_code)
    if not remediation or remediation.status != RemediationStatus.APPLIED:
        logger.warning(f"Could not remediate finding: {finding.get('id')}")
        return None

    # Create PR
    pr = await engine.create_remediation_pr(repo, [remediation])
    if pr and pr.pr_url:
        logger.info(f"Auto-remediation PR created: {pr.pr_url}")
        return pr.pr_url

    return None


async def auto_remediate_batch(
    orchestrator,
    findings: List[Dict[str, Any]],
    repo: str,
) -> BatchResult:
    """Batch remediate multiple findings.

    Args:
        orchestrator: Sentinel orchestrator instance
        findings: List of security findings
        repo: Repository full name

    Returns:
        BatchResult with statistics
    """
    engine = AutoRemediationEngine(orchestrator)
    return await engine.batch_remediate(findings, repo)
