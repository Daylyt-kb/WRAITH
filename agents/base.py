"""
WRAITH v2.0 — Base Agent Class
All agents inherit from WraithAgent. Supports plugin registration,
AI provider injection, sandbox access, and structured logging.
"""

import logging
from datetime import datetime
from typing import Optional, Any


class WraithAgent:
    """
    Base class for all WRAITH agents.

    Each agent declares its metadata as class attributes and inherits
    common functionality: AI provider access, sandbox execution, logging,
    and standardized run() output format.

    Subclasses must implement run(target, scope) -> dict.
    Subclasses may override discover_tools() and execute_with_ai().

    Usage:
        class MyAgent(WraithAgent):
            name = "myagent"
            version = "2.0.0"
            tools = ["nmap"]
            sandbox_profile = "recon"
            risk_level = "low"

            def run(self, target, scope):
                ...
    """

    # ── Agent metadata (override in subclasses) ──
    name: str = "base"
    version: str = "2.0.0"
    description: str = "Base agent class"
    category: str = "general"
    tools: list = []
    sandbox_profile: Optional[str] = None
    risk_level: str = "low"  # low, medium, high, critical
    pro_only: bool = False

    def __init__(self, bus=None, ai_provider=None, sandbox_manager=None,
                 config=None, api_key: str = "", **kwargs):
        """
        Initialize the agent.

        Args:
            bus: MessageBus instance for inter-agent communication
            ai_provider: AIProvider instance for AI-powered analysis
            sandbox_manager: SandboxManager for ephemeral tool execution
            config: Full config dict
            api_key: Legacy API key string (for backward compatibility)
            **kwargs: Additional arguments for backward compatibility
        """
        self.bus = bus
        self.ai = ai_provider
        self.sandbox = sandbox_manager
        self.config = config or {}
        self.api_key = api_key
        self.logger = logging.getLogger(f"wraith.agent.{self.name}")

    def run(self, target: str, scope) -> dict:
        """
        Execute the agent's primary mission.

        Args:
            target: Target domain, IP, or URL
            scope: ScopeValidator instance

        Returns:
            dict with at minimum: {"agent": name, "target": target,
            "findings": list, "summary": str, "finding_count": int}
        """
        raise NotImplementedError(f"Agent '{self.name}' must implement run()")

    def discover_tools(self) -> list:
        """
        Discover which declared tools are available on the system.
        Checks both local installation and sandbox images.

        Returns:
            List of available tool names
        """
        from core.kali_tools import check_tools
        status = check_tools()
        available = set(status.get("available", {}).keys())
        return [t for t in self.tools if t in available]

    def execute_with_ai(self, task: str, system: str = "",
                         max_tokens: int = 1000) -> str:
        """
        Execute a task using the AI provider.
        Returns fallback text if no AI is configured.
        """
        if self.ai and self.ai.is_configured():
            try:
                return self.ai.complete(task, system=system, max_tokens=max_tokens)
            except Exception as e:
                self.logger.warning(f"AI execution failed: {e}")
        return f"[AI: Offline] No AI provider configured for {self.name}"

    def emit(self, event: str, data: dict = None):
        """Emit an event to the message bus."""
        if self.bus:
            self.bus.emit(event, data or {})

    def _safe_run_time(self, start: datetime) -> int:
        """Calculate duration in safely."""
        return (datetime.now() - start).seconds

    def _make_result(self, target: str, findings: list, summary: str,
                      start: datetime, **extra) -> dict:
        """Build a standardized result dict."""
        result = {
            "agent": self.name,
            "target": target,
            "timestamp": start.isoformat(),
            "duration_seconds": self._safe_run_time(start),
            "findings": findings,
            "summary": summary,
            "finding_count": len(findings),
        }
        result.update(extra)
        return result

    def to_dict(self) -> dict:
        """Serialize agent metadata for plugin registry."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "tools": self.tools,
            "sandbox_profile": self.sandbox_profile,
            "risk_level": self.risk_level,
            "pro_only": self.pro_only,
        }

    def __repr__(self):
        return f"<WraithAgent:{self.name} v{self.version}>"
