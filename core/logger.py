"""
WRAITH v2.0 — Structured JSON Logger
Configurable via config.yaml. Supports file + console output with rotation.
"""

import os
import json
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)
        # Include any extra fields
        for key in ("agent", "target", "tool", "duration", "mission_id"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry, default=str)


class WraithLogger:
    """
    WRAITH structured logger.

    Usage:
        from core.logger import get_logger
        log = get_logger("ghost")
        log.info("Scan complete", extra={"target": "example.com", "duration": 12})
    """

    _initialized = False
    _log_dir: Optional[Path] = None
    _level = logging.INFO
    _format = "json"
    _max_bytes = 50 * 1024 * 1024  # 50MB
    _backup_count = 5

    @classmethod
    def setup(cls, config: dict = None):
        """Initialize logging from config dict."""
        if config is None:
            config = {}

        log_config = config.get("logging", {})
        cls._level = getattr(logging, log_config.get("level", "INFO").upper(), logging.INFO)
        cls._format = log_config.get("format", "json")
        cls._max_bytes = log_config.get("max_size_mb", 50) * 1024 * 1024
        cls._backup_count = log_config.get("backup_count", 5)

        # Create log directory
        log_file = log_config.get("file", "wraith_output/wraith.log")
        cls._log_dir = Path(log_file).parent
        cls._log_dir.mkdir(parents=True, exist_ok=True)

        # Configure root logger
        root = logging.getLogger("wraith")
        root.setLevel(cls._level)
        root.handlers.clear()

        # Console handler
        console = logging.StreamHandler()
        console.setLevel(cls._level)
        if cls._format == "json":
            console.setFormatter(JSONFormatter())
        else:
            console.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            ))
        root.addHandler(console)

        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=cls._max_bytes,
            backupCount=cls._backup_count,
        )
        file_handler.setLevel(cls._level)
        if cls._format == "json":
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            ))
        root.addHandler(file_handler)

        cls._initialized = True

    @classmethod
    def setup_from_config(cls, config_path: str = "config.yaml"):
        """Load config from YAML and initialize logging."""
        try:
            from core.config import Config
            cfg = Config(config_path)
            cls.setup(cfg.get())
        except Exception:
            # Fallback to defaults
            cls.setup()

    @classmethod
    def get(cls, name: str) -> logging.Logger:
        """Get a named logger."""
        if not cls._initialized:
            cls.setup()
        return logging.getLogger(f"wraith.{name}")


# Module-level convenience function
def get_logger(name: str) -> logging.Logger:
    """Get a named WRAITH logger."""
    return WraithLogger.get(name)
