"""
WRAITH v2.0 — Supabase Storage Layer
Falls back to local JSON storage when Supabase is not configured.
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

LOCAL_STORAGE_DIR = Path("wraith_output/local_store")


class SupabaseStore:
    """
    User profiles, rate limiting, mission storage.
    Falls back to local JSON files when Supabase URL/key are not set.
    """

    def __init__(self, url: str = "", key: str = ""):
        self.url = url or os.environ.get("SUPABASE_URL", "")
        self.key = key or os.environ.get("SUPABASE_KEY", "")
        self._local_mode = not (self.url and self.key)
        self._local_dir = self._resolve_local_dir()
        if self._local_mode:
            self._local_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _resolve_local_dir() -> Path:
        """Resolve the local storage directory from the module-level setting."""
        import core.supabase_store as _mod
        return Path(_mod.LOCAL_STORAGE_DIR)

    # ── User Profiles ──────────────────────────────────────────────────────

    def create_user_profile(self, user_id: str, email: str, tier: str = "free") -> dict:
        """Create or update a user profile."""
        profile = {
            "id": user_id,
            "email": email,
            "tier": tier,
            "created_at": datetime.utcnow().isoformat(),
            "invite_count": 0,
        }
        if self._local_mode:
            self._local_write(f"user_{user_id}.json", profile)
        return profile

    def get_user_profile(self, user_id: str) -> Optional[dict]:
        """Get a user profile by ID."""
        if self._local_mode:
            return self._local_read(f"user_{user_id}.json")
        return None

    # ── Rate Limiting ──────────────────────────────────────────────────────

    TIER_LIMITS = {
        "free": 10,
        "pro": 100,
        "enterprise": 1000,
    }

    def check_rate_limit(self, user_id: str, tier: str = "free") -> dict:
        """Check if a user is within their daily scan limit."""
        limit = self.TIER_LIMITS.get(tier, 10)
        today = datetime.utcnow().strftime("%Y-%m-%d")
        usage = self._get_daily_usage(user_id, today)
        allowed = usage < limit
        return {
            "allowed": allowed,
            "daily_usage": usage,
            "limit": limit,
            "remaining": max(0, limit - usage),
        }

    def _get_daily_usage(self, user_id: str, date_str: str) -> int:
        """Get the number of scans a user has done on a given date."""
        key = f"usage_{user_id}_{date_str}"
        if self._local_mode:
            data = self._local_read(f"{key}.json")
            if data:
                return data.get("count", 0)
        return 0

    def increment_usage(self, user_id: str):
        """Record a scan for rate limiting."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        key = f"usage_{user_id}_{today}"
        if self._local_mode:
            data = self._local_read(f"{key}.json") or {"count": 0}
            data["count"] = data.get("count", 0) + 1
            self._local_write(f"{key}.json", data)

    # ── Mission Storage ────────────────────────────────────────────────────

    def store_scan(self, user_id: str, target: str, mode: str,
                   findings: list, report: str) -> dict:
        """Store a scan result."""
        record = {
            "id": f"scan_{int(datetime.utcnow().timestamp())}",
            "user_id": user_id,
            "target": target,
            "mode": mode,
            "findings": findings,
            "report": report,
            "created_at": datetime.utcnow().isoformat(),
        }
        if self._local_mode:
            self._local_write(f"scan_{record['id']}.json", record)
        self.increment_usage(user_id)
        return record

    # ── Learning Storage ───────────────────────────────────────────────────

    def store_learning(self, finding_type: str, title: str,
                       severity: str, data: dict) -> dict:
        """Store a learning record."""
        record = {
            "id": f"learn_{int(datetime.utcnow().timestamp())}",
            "finding_type": finding_type,
            "title": title,
            "severity": severity,
            "data": data,
            "created_at": datetime.utcnow().isoformat(),
        }
        if self._local_mode:
            self._local_write(f"learn_{record['id']}.json", record)
        return record

    # ── Invite System ──────────────────────────────────────────────────────

    def get_invite_count(self, user_id: str) -> int:
        """Get the number of invites a user has."""
        if self._local_mode:
            data = self._local_read(f"invites_{user_id}.json")
            if data:
                return data.get("count", 0)
        return 0

    # ── Security Events ────────────────────────────────────────────────────

    def log_security_event(self, user_id: str, event_type: str, data: dict):
        """Log a security event for anti-abuse."""
        event = {
            "user_id": user_id,
            "event_type": event_type,
            "data": data,
            "created_at": datetime.utcnow().isoformat(),
        }
        if self._local_mode:
            events = self._local_read("security_events.json") or []
            events.append(event)
            self._local_write("security_events.json", events)

    def get_security_events(self, user_id: str, event_type: str) -> list:
        """Get security events for a user and type."""
        if self._local_mode:
            events = self._local_read("security_events.json") or []
            return [e for e in events if e.get("user_id") == user_id and e.get("event_type") == event_type]
        return []

    # ── Email Change Protection ─────────────────────────────────────────────

    def can_change_email(self, user_id: str) -> dict:
        """Check if user can change email (once per 7 days)."""
        events = self.get_security_events(user_id, "email_change")
        if not events:
            return {"allowed": True}
        # Sort by date descending
        events.sort(key=lambda e: e.get("created_at", ""), reverse=True)
        last_change = events[0].get("created_at", "")
        if last_change:
            try:
                last_dt = datetime.fromisoformat(last_change)
                if datetime.utcnow() - last_dt < timedelta(days=7):
                    return {"allowed": False, "reason": "Email can only be changed once per 7 days"}
            except Exception:
                pass
        return {"allowed": True}

    def record_email_change(self, user_id: str, old_email: str, new_email: str):
        """Record an email change."""
        self.log_security_event(user_id, "email_change", {
            "old_email": old_email,
            "new_email": new_email,
        })

    # ── Local Storage Helpers ──────────────────────────────────────────────

    def _local_write(self, filename: str, data):
        """Write data to a local JSON file."""
        base = self._resolve_local_dir()
        path = base / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _local_read(self, filename: str) -> Optional[dict]:
        """Read data from a local JSON file."""
        base = self._resolve_local_dir()
        path = base / filename
        if path.exists():
            try:
                with open(path) as f:
                    return json.load(f)
            except Exception:
                return None
        return None


# Module-level singleton
_store_instance: Optional[SupabaseStore] = None


def get_store() -> SupabaseStore:
    """Get the global SupabaseStore instance."""
    global _store_instance
    if _store_instance is None:
        _store_instance = SupabaseStore()
    return _store_instance
