"""
WRAITH v2.0 — Configuration Manager
YAML-based config with environment variable substitution.
Supports profiles, dot-notation access, and hot-reload.
"""

import os
import re
import yaml
from pathlib import Path
from copy import deepcopy


class Config:
    """
    WRAITH configuration manager.
    
    Loads from config.yaml with ${ENV_VAR} substitution.
    Supports dot-notation access: config.get("ai.default_provider")
    Supports profiles: default, offensive, stealth, osint
    
    Usage:
        config = Config("config.yaml")
        provider = config.get("ai.default_provider", "ollama")
        api_key = config.get("ai.providers.anthropic.api_key")
    """

    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self._config = {}
        self._load()

    def _load(self):
        """Load and parse the YAML config file."""
        if not self.config_path.exists():
            self._config = self._default_config()
            return

        with open(self.config_path, "r") as f:
            raw = f.read()

        # Substitute environment variables: ${VAR_NAME} or ${VAR_NAME:-default}
        raw = self._substitute_env(raw)
        self._config = yaml.safe_load(raw) or {}

    def _substitute_env(self, text: str) -> str:
        """Replace ${VAR} and ${VAR:-default} with environment variable values."""
        def replacer(match):
            var_expr = match.group(1)
            if ":-" in var_expr:
                var_name, default = var_expr.split(":-", 1)
            else:
                var_name, default = var_expr, ""
            return os.environ.get(var_name.strip(), default)

        return re.sub(r'\$\{([^}]+)\}', replacer, text)

    def get(self, key: str = None, default=None):
        """
        Get a config value using dot-notation.
        
        Args:
            key: Dot-notation key like "ai.providers.anthropic.model"
                  Returns entire config if None
            default: Default value if key not found
            
        Returns:
            The config value or default
        """
        if key is None:
            return deepcopy(self._config)

        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return deepcopy(value)

    def set(self, key: str, value):
        """Set a config value using dot-notation."""
        keys = key.split(".")
        config = self._config
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def save(self, path: str = None):
        """Save current config to YAML file."""
        save_path = Path(path) if path else self.config_path
        with open(save_path, "w") as f:
            yaml.dump(self._config, f, default_flow_style=False, sort_keys=False)

    def reload(self):
        """Reload config from disk."""
        self._load()

    def _default_config(self) -> dict:
        """Return the default WRAITH v2.0 configuration."""
        return {
            "version": "2.0.0",
            "project": "WRAITH",
            "tagline": "The World's First Civilian AI Security Swarm — GOD TIER",
            "ai": {
                "default_provider": "${WRAITH_AI_PROVIDER:-ollama}",
                "default_model": "${WRAITH_AI_MODEL:-llama3.1:70b}",
                "failover": {
                    "enabled": True,
                    "order": ["ollama", "groq", "anthropic", "openai"]
                },
                "providers": {
                    "anthropic": {
                        "api_key": "${ANTHROPIC_API_KEY}",
                        "model": "claude-sonnet-4-20250514",
                        "base_url": "https://api.anthropic.com"
                    },
                    "openai": {
                        "api_key": "${OPENAI_API_KEY}",
                        "model": "gpt-4o",
                        "base_url": "https://api.openai.com/v1"
                    },
                    "gemini": {
                        "api_key": "${GEMINI_API_KEY}",
                        "model": "gemini-1.5-pro",
                        "base_url": "https://generativelanguage.googleapis.com"
                    },
                    "groq": {
                        "api_key": "${GROQ_API_KEY}",
                        "model": "llama-3.3-70b-versatile",
                        "base_url": "https://api.groq.com/openai/v1"
                    },
                    "mistral": {
                        "api_key": "${MISTRAL_API_KEY}",
                        "model": "mistral-large-latest",
                        "base_url": "https://api.mistral.ai/v1"
                    },
                    "ollama": {
                        "api_key": "ollama-local",
                        "model": "${OLLAMA_MODEL:-llama3.1:70b}",
                        "base_url": "${OLLAMA_HOST:-http://localhost:11434}"
                    },
                    "lmstudio": {
                        "api_key": "lmstudio-local",
                        "model": "local-model",
                        "base_url": "http://localhost:1234/v1"
                    },
                    "custom": {
                        "api_key": "${CUSTOM_API_KEY}",
                        "model": "custom-model",
                        "base_url": "${CUSTOM_API_URL}"
                    }
                }
            },
            "sandbox": {
                "enabled": True,
                "engine": "docker",
                "network_isolation": True,
                "auto_cleanup": True,
                "max_containers": 5,
                "timeout": 300,
                "profiles": {
                    "recon": {
                        "image": "wraith-recon:latest",
                        "tools": ["nmap", "masscan", "amass", "subfinder", "httpx", "dnsenum", "fierce"]
                    },
                    "web": {
                        "image": "wraith-web:latest",
                        "tools": ["sqlmap", "nikto", "gobuster", "ffuf", "wpscan", "xsser"]
                    },
                    "exploit": {
                        "image": "wraith-exploit:latest",
                        "tools": ["msfconsole", "searchsploit", "sploitctl"]
                    },
                    "osint": {
                        "image": "wraith-osint:latest",
                        "tools": ["maltego", "sherlock", "theHarvester", "recon-ng", "spiderfoot"]
                    },
                    "wireless": {
                        "image": "wraith-wireless:latest",
                        "tools": ["aircrack-ng", "kismet", "wifite", "reaver"],
                        "requires_vm": True
                    },
                    "custom": {
                        "image": "kalilinux/kali-rolling:latest",
                        "tools": []
                    }
                }
            },
            "agents": {
                "default_model_per_agent": {
                    "ghost": "groq",
                    "specter": "ollama",
                    "scanner": "groq",
                    "breach": "anthropic",
                    "forge": "anthropic",
                    "mirror": "openai",
                    "neuron": "ollama",
                    "ledger": "ollama",
                    "commander": "anthropic"
                }
            },
            "web": {
                "host": "0.0.0.0",
                "port": 1337,
                "debug": False,
                "secret_key": "${WRAITH_SECRET_KEY:-wraith-v2-god-tier}",
                "websocket_enabled": True
            },
            "license": {
                "enabled": True,
                "type": "open_core",
                "pro_features": [
                    "phantom", "orchestrator", "sentinel",
                    "metasploit", "pdf_reports", "compliance_mapping",
                    "batch_scanning", "vm_sandboxes", "dark_web_monitoring"
                ]
            },
            "logging": {
                "level": "INFO",
                "format": "json",
                "file": "wraith_output/wraith.log",
                "max_size_mb": 50,
                "backup_count": 5
            },
            "legal": {
                "require_authorization": True,
                "consent_dir": "wraith_output/consent",
                "audit_log": "wraith_output/audit.log",
                "rate_limit_per_minute": 30,
                "blocked_targets": [
                    "localhost", "127.0.0.1", "0.0.0.0",
                    "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
                ]
            }
        }

    def __repr__(self):
        return f"Config(path={self.config_path}, providers={list(self.get('ai.providers', {}).keys())})"
