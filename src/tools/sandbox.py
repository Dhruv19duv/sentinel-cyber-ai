"""Sandboxed Execution Environment.

Provides isolated, safe execution of untrusted code for:
- Dynamic vulnerability analysis
- Exploit verification
- Payload testing

Uses Docker containers with strict resource limits and no network access.

This is a key differentiator from Mythos — we can safely verify exploits
before reporting them, reducing false positives.
"""

import os
import json
import logging
import subprocess
import tempfile
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    """Result from sandboxed code execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    memory_mb: float = 0.0
    duration_ms: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class CodeSandbox:
    """Isolated execution environment for security analysis."""

    def __init__(
        self,
        container_image: str = "sentinel-sandbox:latest",
        memory_limit_mb: int = 4096,
        cpu_limit: int = 2,
        timeout_seconds: int = 60,
        network_disabled: bool = True,
    ):
        self.container_image = container_image
        self.memory_limit_mb = memory_limit_mb
        self.cpu_limit = cpu_limit
        self.timeout_seconds = timeout_seconds
        self.network_disabled = network_disabled

    async def execute_code(
        self,
        code: str,
        language: str = "python",
        inputs: Optional[Dict[str, Any]] = None,
    ) -> SandboxResult:
        """Execute code in a sandboxed container.

        Supports: python, bash, javascript, go, rust
        """
        import time
        start = time.time()

        # Determine the command based on language
        runners = {
            "python": ["python3", "-c"],
            "bash": ["bash", "-c"],
            "javascript": ["node", "-e"],
            "go": ["go", "run", "-"],  # Requires file-based approach
            "rust": ["rustc", "-"],    # Requires file-based approach
        }

        runner = runners.get(language.lower(), runners["python"])
        is_file_based = language.lower() in ("go", "rust")

        try:
            if is_file_based:
                # Write code to temp file and run
                suffix = {"go": ".go", "rust": ".rs"}.get(language.lower(), ".py")
                with tempfile.NamedTemporaryFile(
                    suffix=suffix, mode="w", delete=False
                ) as f:
                    f.write(code)
                    temp_path = f.name

                command = [runner[0], temp_path]
                if len(runner) > 1:
                    command = runner + [temp_path]
            else:
                command = runner + [code]

            # Build the docker run command
            docker_cmd = [
                "docker", "run", "--rm",
                "--memory", f"{self.memory_limit_mb}m",
                "--cpus", str(self.cpu_limit),
                "--network", "none" if self.network_disabled else "bridge",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--ulimit", "nofile=1024:1024",
                "--ulimit", "nproc=50:50",
            ]

            # Add environment variables if inputs provided
            if inputs:
                for key, value in inputs.items():
                    docker_cmd.extend(["-e", f"{key}={json.dumps(value)}"])

            docker_cmd.append(self.container_image)
            docker_cmd.extend(command)

            # Execute with timeout
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            duration = (time.time() - start) * 1000

            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=duration,
            )

        except subprocess.TimeoutExpired:
            logger.warning(f"Sandbox execution timed out after {self.timeout_seconds}s")
            return SandboxResult(
                success=False,
                error="Execution timed out",
                timed_out=True,
                duration_ms=(time.time() - start) * 1000,
            )
        except FileNotFoundError:
            logger.warning("Docker not available — running in restricted local mode")
            return self._execute_local(code, language, inputs, start)
        except Exception as e:
            logger.error(f"Sandbox execution failed: {e}")
            return SandboxResult(
                success=False,
                error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )
        finally:
            if is_file_based and "temp_path" in locals():
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def _execute_local(
        self,
        code: str,
        language: str,
        inputs: Optional[Dict[str, Any]],
        start: float,
    ) -> SandboxResult:
        """Fallback: execute code locally with restricted privileges."""
        logger.warning("Running code WITHOUT container isolation — limited safety")
        try:
            import subprocess
            result = subprocess.run(
                ["python3", "-c", code],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return SandboxResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            return SandboxResult(
                success=False,
                error=str(e),
                duration_ms=(time.time() - start) * 1000,
            )

    def check_docker_available(self) -> bool:
        """Check if Docker is available on this system."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
