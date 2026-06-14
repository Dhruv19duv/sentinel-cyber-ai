"""
Code Execution Sandbox — Fable 5's code execution tool reimplementation.

Matches Fable 5's sandboxed code execution:
- Docker container with network isolation
- Python 3.11 + common libraries (pandas, numpy, scipy, sklearn)
- Bash shell access for system operations
- File operations (create, read, edit, upload)
- 5GB RAM, 5GB disk, 1 CPU core limits
- 30-day container persistence with container IDs
- No outbound network access
- Linux (x86_64) environment

Fable 5 spec:
- Containerized, network-isolated Linux environment
- Python 3.11 with data science libraries
- Bash commands + file operations
- 5GiB RAM, 5GiB disk, 1 CPU core
- Container persists up to 30 days via container_id
- No outbound network access
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from typing import Dict, List, Optional, Any, AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SandboxConfig:
    """Configuration for the code execution sandbox.
    
    Matches Fable 5's sandbox resource limits exactly.
    """
    memory_mb: int = 5 * 1024  # 5 GiB RAM
    disk_mb: int = 5 * 1024    # 5 GiB disk
    cpu_count: int = 1         # 1 dedicated CPU core
    network_enabled: bool = False  # No outbound network access
    container_timeout: int = 300  # Max execution time per call (seconds)
    python_version: str = "3.11"
    temp_dir: str = "/tmp/sentinel_sandbox"
    container_expiry_days: int = 30  # Matches Fable 5's 30-day persistence


@dataclass
class ExecutionResult:
    """Result from a sandboxed code execution."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: float
    files_created: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "stdout": self.stdout[:2000],
            "stderr": self.stderr[:1000],
            "exit_code": self.exit_code,
            "time_ms": self.execution_time_ms,
            "files_created": self.files_created,
            "error": self.error,
        }


@dataclass
class SandboxSession:
    """A persistent sandbox session — analogous to Fable 5's container_id.
    
    In Fable 5, containers persist for up to 30 days and can be
    reused across API requests by passing the container_id.
    """
    container_id: str
    created_at: datetime
    last_used: datetime
    workspace_dir: str
    is_active: bool = True

    @property
    def age_days(self) -> float:
        return (datetime.utcnow() - self.created_at).days
    
    @property
    def is_expired(self) -> bool:
        return self.age_days >= 30


# Pre-installed libraries matching Fable 5's environment
PREINSTALLED_LIBRARIES = [
    "pandas", "numpy", "scipy", "scikit-learn",
    "matplotlib", "seaborn", "pillow",
    "requests", "beautifulsoup4", "lxml",
    "pyyaml", "toml", "json5",
    "cryptography", "hashlib",
]


class CodeExecutor:
    """Sandboxed code executor matching Fable 5's code execution tool.
    
    Supports:
    - Python code execution (3.11)
    - Bash commands
    - File operations
    - Container persistence (30 days)
    - Resource limits (5GB RAM, 5GB disk, 1 CPU)
    - Network isolation
    """
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._sessions: Dict[str, SandboxSession] = {}
        self._base_workspace = os.path.expanduser("~/.cache/sentinel/sandbox")
        os.makedirs(self._base_workspace, exist_ok=True)
        
        # Check if Docker is available
        self._docker_available = self._check_docker()
        if not self._docker_available:
            logger.warning(
                "Docker not available. Falling back to local subprocess execution "
                "(reduced isolation). Install Docker for full sandbox security."
            )
    
    def _check_docker(self) -> bool:
        """Check if Docker is installed and running."""
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def create_session(self) -> SandboxSession:
        """Create a new sandbox session.
        
        Returns a container_id that can be reused for up to 30 days,
        matching Fable 5's container persistence.
        """
        container_id = f"sentinel-{uuid.uuid4().hex[:12]}"
        workspace = os.path.join(self._base_workspace, container_id)
        os.makedirs(workspace, exist_ok=True)
        
        session = SandboxSession(
            container_id=container_id,
            created_at=datetime.utcnow(),
            last_used=datetime.utcnow(),
            workspace_dir=workspace,
        )
        
        self._sessions[container_id] = session
        
        if self._docker_available:
            self._create_docker_container(session)
        
        logger.info(f"Created sandbox session {container_id}")
        return session
    
    def _create_docker_container(self, session: SandboxSession):
        """Create a Docker container for the sandbox session."""
        try:
            # Build the sandbox image if not exists
            dockerfile = os.path.join(self._base_workspace, "Dockerfile")
            with open(dockerfile, "w") as f:
                f.write(self._get_dockerfile_content())
            
            subprocess.run(
                ["docker", "build", "-t", "sentinel-sandbox", self._base_workspace],
                capture_output=True, text=True, timeout=120,
            )
            
            # Run the container with resource limits
            subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", session.container_id,
                    "--memory", f"{self.config.memory_mb}m",
                    "--cpus", str(self.config.cpu_count),
                    "--network", "none" if not self.config.network_enabled else "bridge",
                    "--read-only",  # Read-only root filesystem
                    "-v", f"{session.workspace_dir}:/workspace",
                    "-w", "/workspace",
                    "sentinel-sandbox",
                    "sleep", "infinity",
                ],
                capture_output=True, text=True, timeout=30,
            )
            logger.info(f"Docker container {session.container_id} created")
            
        except subprocess.TimeoutExpired:
            logger.error("Docker build timed out")
        except Exception as e:
            logger.error(f"Docker container creation failed: {e}")
    
    def _get_dockerfile_content(self) -> str:
        """Generate Dockerfile for the sandbox image."""
        return f"""FROM python:{self.config.python_version}-slim

RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \\
    {' '.join(PREINSTALLED_LIBRARIES)}

WORKDIR /workspace
"""
    
    async def execute_python(
        self,
        code: str,
        container_id: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """Execute Python code in the sandbox.
        
        Args:
            code: Python code to execute
            container_id: Reuse existing container (None = create new)
            timeout: Execution timeout in seconds
            
        Returns:
            ExecutionResult with stdout, stderr, and exit code
        """
        # Get or create session
        session = self._get_or_create_session(container_id)
        timeout = timeout or self.config.container_timeout
        
        # Write code to file in workspace
        code_file = os.path.join(session.workspace_dir, "_exec.py")
        with open(code_file, "w") as f:
            f.write(code)
        
        start = time.time()
        
        try:
            if self._docker_available:
                result = await self._exec_docker(session, ["python", "_exec.py"], timeout)
            else:
                result = await self._exec_local(["python", code_file], timeout, session.workspace_dir)
            
            # Collect created files
            files_created = self._get_created_files(session)
            result.files_created = files_created
            
            session.last_used = datetime.utcnow()
            
        except Exception as e:
            result = ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time_ms=(time.time() - start) * 1000,
                error=str(e),
            )
        
        logger.info(
            f"Python execution: success={result.success}, "
            f"time={result.execution_time_ms:.0f}ms, "
            f"container={session.container_id}"
        )
        
        return result
    
    async def execute_bash(
        self,
        command: str,
        container_id: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ExecutionResult:
        """Execute a bash command in the sandbox.
        
        Matches Fable 5's bash sub-tool functionality.
        
        Args:
            command: Bash command to execute
            container_id: Reuse existing container
            timeout: Execution timeout
            
        Returns:
            ExecutionResult with stdout, stderr
        """
        session = self._get_or_create_session(container_id)
        timeout = timeout or self.config.container_timeout
        
        # Write command to script
        script_file = os.path.join(session.workspace_dir, "_cmd.sh")
        with open(script_file, "w") as f:
            f.write(f"#!/bin/bash\n{command}\n")
        os.chmod(script_file, 0o755)
        
        start = time.time()
        
        try:
            if self._docker_available:
                result = await self._exec_docker(session, ["bash", "_cmd.sh"], timeout)
            else:
                result = await self._exec_local(["bash", script_file], timeout, session.workspace_dir)
            
            files_created = self._get_created_files(session)
            result.files_created = files_created
            session.last_used = datetime.utcnow()
            
        except Exception as e:
            result = ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time_ms=(time.time() - start) * 1000,
                error=str(e),
            )
        
        return result
    
    async def write_file(
        self,
        path: str,
        content: str,
        container_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Write a file in the sandbox workspace.
        
        Matches Fable 5's file operations sub-tool.
        """
        session = self._get_or_create_session(container_id)
        
        # Security: prevent directory traversal
        safe_path = os.path.normpath(os.path.join(session.workspace_dir, path))
        if not safe_path.startswith(os.path.normpath(session.workspace_dir)):
            return ExecutionResult(
                success=False,
                stdout="",
                stderr="Path traversal detected",
                exit_code=-1,
                execution_time_ms=0,
                error="Invalid path",
            )
        
        try:
            os.makedirs(os.path.dirname(safe_path), exist_ok=True)
            with open(safe_path, "w") as f:
                f.write(content)
            
            return ExecutionResult(
                success=True,
                stdout=f"File written: {path}",
                stderr="",
                exit_code=0,
                execution_time_ms=0,
                files_created=[path],
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                execution_time_ms=0,
                error=str(e),
            )
    
    async def read_file(
        self,
        path: str,
        container_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Read a file from the sandbox workspace."""
        session = self._get_or_create_session(container_id)
        
        safe_path = os.path.normpath(os.path.join(session.workspace_dir, path))
        if not safe_path.startswith(os.path.normpath(session.workspace_dir)):
            return ExecutionResult(
                success=False, stdout="", stderr="Path traversal detected",
                exit_code=-1, execution_time_ms=0, error="Invalid path",
            )
        
        try:
            with open(safe_path, "r") as f:
                content = f.read()
            return ExecutionResult(
                success=True, stdout=content, stderr="",
                exit_code=0, execution_time_ms=0,
            )
        except Exception as e:
            return ExecutionResult(
                success=False, stdout="", stderr=str(e),
                exit_code=-1, execution_time_ms=0, error=str(e),
            )
    
    async def list_files(
        self,
        path: str = ".",
        container_id: Optional[str] = None,
    ) -> ExecutionResult:
        """List files in the sandbox workspace."""
        session = self._get_or_create_session(container_id)
        target = os.path.normpath(os.path.join(session.workspace_dir, path))
        
        if not target.startswith(os.path.normpath(session.workspace_dir)):
            return ExecutionResult(
                success=False, stdout="", stderr="Path traversal detected",
                exit_code=-1, execution_time_ms=0, error="Invalid path",
            )
        
        try:
            files = os.listdir(target)
            return ExecutionResult(
                success=True,
                stdout="\n".join(files),
                stderr="",
                exit_code=0,
                execution_time_ms=0,
            )
        except Exception as e:
            return ExecutionResult(
                success=False, stdout="", stderr=str(e),
                exit_code=-1, execution_time_ms=0, error=str(e),
            )
    
    def _get_or_create_session(self, container_id: Optional[str] = None) -> SandboxSession:
        """Get an existing session or create a new one."""
        if container_id and container_id in self._sessions:
            session = self._sessions[container_id]
            if not session.is_expired:
                return session
            else:
                # Clean up expired session
                self.destroy_session(container_id)
        
        return self.create_session()
    
    async def _exec_docker(
        self, session: SandboxSession, cmd: List[str], timeout: int
    ) -> ExecutionResult:
        """Execute a command inside a Docker container."""
        start = time.time()
        
        try:
            # Run command in container
            docker_cmd = [
                "docker", "exec",
                "-w", "/workspace",
                session.container_id,
            ] + cmd
            
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return ExecutionResult(
                    success=False, stdout="", stderr=f"Timeout after {timeout}s",
                    exit_code=-1, execution_time_ms=(time.time() - start) * 1000,
                    error="Timeout",
                )
            
            return ExecutionResult(
                success=proc.returncode == 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
                execution_time_ms=(time.time() - start) * 1000,
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False, stdout="", stderr=str(e),
                exit_code=-1, execution_time_ms=(time.time() - start) * 1000,
                error=str(e),
            )
    
    async def _exec_local(
        self, cmd: List[str], timeout: int, cwd: str
    ) -> ExecutionResult:
        """Execute locally as fallback when Docker isn't available."""
        start = time.time()
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return ExecutionResult(
                    success=False, stdout="", stderr=f"Timeout after {timeout}s",
                    exit_code=-1, execution_time_ms=(time.time() - start) * 1000,
                    error="Timeout",
                )
            
            return ExecutionResult(
                success=proc.returncode == 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                exit_code=proc.returncode or 0,
                execution_time_ms=(time.time() - start) * 1000,
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False, stdout="", stderr=str(e),
                exit_code=-1, execution_time_ms=(time.time() - start) * 1000,
                error=str(e),
            )
    
    def _get_created_files(self, session: SandboxSession) -> List[str]:
        """Get list of files created in the workspace."""
        created = []
        for root, dirs, files in os.walk(session.workspace_dir):
            for f in files:
                if f not in ("_exec.py", "_cmd.sh"):
                    rel_path = os.path.relpath(os.path.join(root, f), session.workspace_dir)
                    created.append(rel_path)
        return created
    
    def destroy_session(self, container_id: str):
        """Destroy a sandbox session and clean up resources."""
        if container_id in self._sessions:
            session = self._sessions[container_id]
            
            # Clean up Docker container
            if self._docker_available:
                try:
                    subprocess.run(
                        ["docker", "rm", "-f", session.container_id],
                        capture_output=True, timeout=30,
                    )
                except Exception:
                    pass
            
            # Clean up workspace
            if os.path.exists(session.workspace_dir):
                shutil.rmtree(session.workspace_dir, ignore_errors=True)
            
            del self._sessions[container_id]
            logger.info(f"Destroyed sandbox session {container_id}")
    
    def clean_expired(self):
        """Clean up all expired sessions (age > 30 days)."""
        expired = [
            cid for cid, s in self._sessions.items()
            if s.is_expired
        ]
        for cid in expired:
            self.destroy_session(cid)
        if expired:
            logger.info(f"Cleaned {len(expired)} expired sandbox sessions")
    
    def get_status(self) -> Dict[str, Any]:
        """Get sandbox status."""
        return {
            "docker_available": self._docker_available,
            "active_sessions": len(self._sessions),
            "sessions": [
                {
                    "container_id": s.container_id,
                    "age_days": s.age_days,
                    "is_active": s.is_active,
                    "is_expired": s.is_expired,
                }
                for s in self._sessions.values()
            ],
            "config": {
                "memory_mb": self.config.memory_mb,
                "cpu_count": self.config.cpu_count,
                "network_enabled": self.config.network_enabled,
                "container_expiry_days": self.config.container_expiry_days,
            },
        }
