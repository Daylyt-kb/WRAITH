"""
WRAITH v2.0 — Sandbox Manager
Docker-based ephemeral execution environments for Kali Linux tools.
Agents request tools → sandbox spins up → tools run → sandbox destroyed.

Profiles: recon, web, exploit, osint, wireless, custom
Each profile has a pre-built Docker image with the right tools.
"""

import os
import json
import time
import uuid
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional


class Sandbox:
    """
    A single ephemeral execution environment.
    
    Usage:
        sandbox = Sandbox(profile="recon", tools=["nmap", "masscan"])
        results = sandbox.run("nmap -sV -sC target.com")
        sandbox.destroy()
    """

    def __init__(self, profile: str = "recon", tools: list = None,
                 target: str = "", timeout: int = 300, config: dict = None):
        self.id = f"sandbox_{uuid.uuid4().hex[:8]}"
        self.profile = profile
        self.tools = tools or []
        self.target = target
        self.timeout = timeout
        self.config = config or {}
        self.container_name = f"wraith-{self.id}"
        self.output_dir = Path(tempfile.mkdtemp(prefix=f"wraith_{self.id}_"))
        self.created_at = datetime.now()
        self._running = False
        self._container_id = None

    def is_docker_available(self) -> bool:
        """Check if Docker is installed and running."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def build_image(self, profile: str = None) -> bool:
        """
        Build the Docker image for a profile.
        Uses pre-built Dockerfiles from sandboxes/ directory.
        """
        profile = profile or self.profile
        dockerfile_path = Path(__file__).parent.parent / "sandboxes" / f"Dockerfile.{profile}"
        
        if not dockerfile_path.exists():
            # Fall back to base Kali image
            dockerfile_path = Path(__file__).parent.parent / "sandboxes" / "Dockerfile.kali-base"
        
        if not dockerfile_path.exists():
            return False

        image_tag = f"wraith-{profile}:latest"
        try:
            result = subprocess.run(
                ["docker", "build", "-t", image_tag, "-f", str(dockerfile_path), "."],
                capture_output=True, text=True, timeout=600,
                cwd=str(Path(__file__).parent.parent)
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def run(self, command: str, tool: str = "") -> dict:
        """
        Run a command inside the sandbox.
        
        Args:
            command: The command to execute
            tool: Name of the tool (for logging)
            
        Returns:
            dict with stdout, stderr, return_code, duration
        """
        if not self.is_docker_available():
            return self._run_local(command, tool)

        return self._run_docker(command, tool)

    def _run_docker(self, command: str, tool: str) -> dict:
        """Run command inside a Docker container with on-demand tool install."""
        image = f"wraith-{self.profile}:latest"
        start_time = time.time()

        # Use KaliVMManager to ensure tools are available
        from core.kali_vm import KaliVMManager
        vm = KaliVMManager(profile=self.profile)
        if tool:
            vm.ensure_tools([tool])

        # Build docker run command
        docker_cmd = [
            "docker", "run",
            "--rm",  # Auto-remove after exit
            "--name", self.container_name,
            "--network", "none" if self.config.get("network_isolation", True) else "bridge",
            "--memory", "512m",
            "--cpus", "1.0",
            "-v", f"{self.output_dir}:/output:rw",
            "-e", f"WRAITH_TARGET={self.target}",
            "-e", f"WRAITH_TOOL={tool}",
        ]

        # For network tools, enable network access
        if self.profile in ("recon", "web", "exploit") and not self.config.get("network_isolation"):
            docker_cmd = [c for c in docker_cmd if c not in ("--network", "none")]

        docker_cmd.extend([image, "bash", "-c", command])

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True, text=True, timeout=self.timeout
            )
            duration = time.time() - start_time

            return {
                "tool": tool,
                "command": command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "duration": round(duration, 2),
                "sandbox_id": self.id,
                "engine": "docker"
            }
        except subprocess.TimeoutExpired:
            # Kill the container
            subprocess.run(["docker", "kill", self.container_name], capture_output=True)
            return {
                "tool": tool,
                "command": command,
                "stdout": "",
                "stderr": f"Sandbox timed out after {self.timeout}s",
                "return_code": -1,
                "duration": self.timeout,
                "sandbox_id": self.id,
                "engine": "docker",
                "timed_out": True
            }

    def _run_local(self, command: str, tool: str) -> dict:
        """
        Fallback: run command locally when Docker is not available.
        Used for development and testing.
        """
        start_time = time.time()
        try:
            result = subprocess.run(
                command, shell=True,
                capture_output=True, text=True, timeout=self.timeout,
                cwd=str(self.output_dir)
            )
            duration = time.time() - start_time
            return {
                "tool": tool,
                "command": command,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "duration": round(duration, 2),
                "sandbox_id": self.id,
                "engine": "local"
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": tool,
                "command": command,
                "stdout": "",
                "stderr": f"Command timed out after {self.timeout}s",
                "return_code": -1,
                "duration": self.timeout,
                "sandbox_id": self.id,
                "engine": "local",
                "timed_out": True
            }

    def destroy(self):
        """Destroy the sandbox and clean up all artifacts."""
        # Kill container if running
        if self._container_id:
            subprocess.run(
                ["docker", "kill", self.container_name],
                capture_output=True, timeout=10
            )

        # Remove output directory
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir, ignore_errors=True)

        self._running = False

    def get_output_files(self) -> list:
        """List all output files generated by sandbox commands."""
        if self.output_dir.exists():
            return [str(f) for f in self.output_dir.rglob("*") if f.is_file()]
        return []

    def __repr__(self):
        return f"Sandbox(id={self.id}, profile={self.profile}, tools={self.tools})"


class SandboxManager:
    """
    Manages sandbox lifecycle: creation, pooling, and destruction.
    
    Usage:
        mgr = SandboxManager(config)
        sandbox = mgr.create(profile="recon", tools=["nmap"])
        results = sandbox.run("nmap -sV target.com")
        mgr.destroy(sandbox.id)
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._active_sandboxes = {}
        self._max_containers = self.config.get("sandbox", {}).get("max_containers", 5)

    def create(self, profile: str = "recon", tools: list = None,
               target: str = "", timeout: int = 300) -> Sandbox:
        """
        Create a new sandbox.
        
        Args:
            profile: Sandbox profile (recon, web, exploit, osint, wireless, custom)
            tools: List of tools to ensure are available
            target: Target being tested
            timeout: Maximum execution time in seconds
            
        Returns:
            Sandbox instance
        """
        # Enforce max containers
        self._cleanup_finished()

        if len(self._active_sandboxes) >= self._max_containers:
            # Destroy oldest sandbox
            oldest = min(self._active_sandboxes.values(), key=lambda s: s.created_at)
            self.destroy(oldest.id)

        sandbox = Sandbox(
            profile=profile, tools=tools, target=target,
            timeout=timeout, config=self.config
        )
        self._active_sandboxes[sandbox.id] = sandbox
        return sandbox

    def destroy(self, sandbox_id: str):
        """Destroy a specific sandbox."""
        if sandbox_id in self._active_sandboxes:
            self._active_sandboxes[sandbox_id].destroy()
            del self._active_sandboxes[sandbox_id]

    def destroy_all(self):
        """Destroy all active sandboxes."""
        for sandbox in self._active_sandboxes.values():
            sandbox.destroy()
        self._active_sandboxes.clear()

    def get_active(self) -> list:
        """List all active sandboxes."""
        return list(self._active_sandboxes.values())

    def _cleanup_finished(self):
        """Remove sandboxes that have been running too long."""
        now = datetime.now()
        to_remove = []
        for sid, sandbox in self._active_sandboxes.items():
            age = (now - sandbox.created_at).total_seconds()
            if age > sandbox.timeout * 2:  # 2x timeout = definitely done
                to_remove.append(sid)
        for sid in to_remove:
            self.destroy(sid)

    @staticmethod
    def check_docker() -> dict:
        """Check Docker availability and return status info."""
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return {
                    "available": True,
                    "version": result.stdout.strip(),
                    "engine": "docker"
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check for Podman as alternative
        try:
            result = subprocess.run(
                ["podman", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return {
                    "available": True,
                    "version": result.stdout.strip(),
                    "engine": "podman"
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return {
            "available": False,
            "version": None,
            "engine": None,
            "fallback": "local_execution"
        }

    def __repr__(self):
        return f"SandboxManager(active={len(self._active_sandboxes)}, max={self._max_containers})"
