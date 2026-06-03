"""
WRAITH v2.0 — Plugin System
Auto-discovers agents from the agents/ directory.
Each agent is a plugin that registers itself.
"""

import os
import sys
import importlib
import inspect
from pathlib import Path
from typing import Dict, Type, Optional


class PluginRegistry:
    """
    Auto-discovers and manages WRAITH agent plugins.
    
    Agents register by inheriting from WraithAgent base class.
    The registry scans agents/ directory and loads all plugins.
    
    Usage:
        registry = PluginRegistry()
        registry.discover()
        ghost = registry.create("ghost", ai_provider, sandbox_mgr, config)
        all_agents = registry.list_agents()
    """

    def __init__(self, agents_dir: str = None):
        self.agents_dir = agents_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "agents"
        )
        self._plugins: Dict[str, Type] = {}
        self._metadata: Dict[str, dict] = {}

    def discover(self) -> int:
        """
        Scan agents/ directory and register all agent plugins.
        Returns the number of agents discovered.
        """
        agents_path = Path(self.agents_dir)
        if not agents_path.exists():
            return 0

        # Add agents dir to path for imports
        if str(agents_path.parent) not in sys.path:
            sys.path.insert(0, str(agents_path.parent))

        for file_path in agents_path.glob("*.py"):
            if file_path.name.startswith("_"):
                continue

            module_name = f"agents.{file_path.stem}"
            try:
                module = importlib.import_module(module_name)
                self._register_from_module(module)
            except Exception as e:
                # Skip modules that fail to import (missing deps, etc.)
                pass

        return len(self._plugins)

    def _register_from_module(self, module):
        """Find and register all agent classes in a module."""
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # Look for classes with agent metadata
            if hasattr(obj, 'agent_name') or hasattr(obj, 'name'):
                agent_id = getattr(obj, 'agent_name', None) or getattr(obj, 'name', name.lower())
                self._plugins[agent_id] = obj
                self._metadata[agent_id] = {
                    "class_name": name,
                    "module": module.__name__,
                    "description": getattr(obj, 'description', ''),
                    "category": getattr(obj, 'category', 'general'),
                    "risk_level": getattr(obj, 'risk_level', 'low'),
                    "tools": getattr(obj, 'tools', []),
                    "sandbox_profile": getattr(obj, 'sandbox_profile', None),
                    "pro_only": getattr(obj, 'pro_only', False),
                }

    def register(self, agent_id: str, agent_class: Type, metadata: dict = None):
        """Manually register an agent plugin."""
        self._plugins[agent_id] = agent_class
        self._metadata[agent_id] = metadata or {}

    def create(self, agent_id: str, *args, **kwargs):
        """Instantiate an agent by ID."""
        if agent_id not in self._plugins:
            raise ValueError(f"Unknown agent: {agent_id}. Available: {list(self._plugins.keys())}")
        return self._plugins[agent_id](*args, **kwargs)

    def get_class(self, agent_id: str) -> Optional[Type]:
        """Get an agent class without instantiating."""
        return self._plugins.get(agent_id)

    def list_agents(self) -> list:
        """List all registered agent IDs."""
        return list(self._plugins.keys())

    def get_metadata(self, agent_id: str) -> Optional[dict]:
        """Get metadata for an agent."""
        return self._metadata.get(agent_id)

    def get_all_metadata(self) -> dict:
        """Get metadata for all agents."""
        return dict(self._metadata)

    def is_pro(self, agent_id: str) -> bool:
        """Check if an agent is pro-only."""
        meta = self._metadata.get(agent_id, {})
        return meta.get("pro_only", False)

    def __repr__(self):
        return f"PluginRegistry(agents={list(self._plugins.keys())})"
