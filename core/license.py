"""
WRAITH v2.0 — License System
Open core + pro features gate.
Simple key-based unlock stored locally.
"""

import os
import json
import hashlib
import hmac
from pathlib import Path
from datetime import datetime


# WRAITH license key format: WRAITH-XXXX-XXXX-XXXX
# Validation is local — no phone-home required
LICENSE_SECRET = os.environ.get("WRAITH_LICENSE_SECRET", "")  # Must be set via env


class LicenseManager:
    """
    Manages WRAITH license validation and feature gating.
    
    Open features: Always available
    Pro features: Require valid license key
    
    Usage:
        license = LicenseManager()
        license.activate("WRAITH-PRO-XXXX-XXXX")
        if license.is_pro("phantom"):
            # Enable dark web monitoring
    """

    # Features that require a pro license
    PRO_FEATURES = {
        "phantom": "Dark web monitoring agent",
        "orchestrator": "Multi-target campaign manager",
        "sentinel": "Continuous monitoring agent",
        "metasploit": "Metasploit Framework integration",
        "pdf_reports": "PDF report generation",
        "compliance_mapping": "ISO 27001 / SOC2 / PCI-DSS mapping",
        "batch_scanning": "Parallel multi-target scanning",
        "vm_sandboxes": "VM-based sandboxes (vs Docker)",
        "dark_web_monitoring": "Dark web credential monitoring",
        "advanced_ai": "Multi-model AI red teaming",
        "api_access": "REST API access",
        "priority_support": "Priority support queue",
    }

    def __init__(self, license_file: str = None):
        self.license_file = Path(license_file or "wraith_output/license.json")
        self.license_file.parent.mkdir(parents=True, exist_ok=True)
        self._license_data = None
        self._load()

    def _load(self):
        """Load license from disk."""
        if self.license_file.exists():
            try:
                with open(self.license_file) as f:
                    self._license_data = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._license_data = None

    def activate(self, license_key: str) -> dict:
        """
        Activate a license key.
        
        Args:
            license_key: License key in format WRAITH-XXXX-XXXX-XXXX
            
        Returns:
            dict with activation status
        """
        # Validate key format
        if not self._validate_format(license_key):
            return {
                "success": False,
                "error": "Invalid license key format. Expected: WRAITH-XXXX-XXXX-XXXX"
            }

        # Validate key signature
        if not self._validate_signature(license_key):
            return {
                "success": False,
                "error": "Invalid license key signature."
            }

        # Determine license type
        license_type = self._get_license_type(license_key)

        self._license_data = {
            "key": self._mask_key(license_key),
            "type": license_type,
            "activated_at": datetime.now().isoformat(),
            "features": list(self.PRO_FEATURES.keys()) if license_type == "pro" else [],
            "valid": True,
        }

        # Save to disk
        with open(self.license_file, "w") as f:
            json.dump(self._license_data, f, indent=2)

        return {
            "success": True,
            "type": license_type,
            "features": self._license_data["features"],
            "message": f"WRAITH {license_type.upper()} activated successfully!"
        }

    def deactivate(self) -> dict:
        """Deactivate the current license."""
        self._license_data = None
        if self.license_file.exists():
            self.license_file.unlink()
        return {"success": True, "message": "License deactivated."}

    def is_pro(self, feature: str = None) -> bool:
        """
        Check if a feature is available.
        Open features are always available.
        Pro features require valid license.
        """
        if feature is None:
            return self.is_activated()

        # Open features are always available
        if feature not in self.PRO_FEATURES:
            return True

        # Check license
        if not self._license_data or not self._license_data.get("valid"):
            return False

        return feature in self._license_data.get("features", [])

    def is_activated(self) -> bool:
        """Check if any valid license is active."""
        return (
            self._license_data is not None
            and self._license_data.get("valid", False)
        )

    def get_status(self) -> dict:
        """Get full license status for dashboard."""
        return {
            "activated": self.is_activated(),
            "type": self._license_data.get("type", "open") if self._license_data else "open",
            "key": self._license_data.get("key", "none") if self._license_data else "none",
            "activated_at": self._license_data.get("activated_at", None) if self._license_data else None,
            "pro_features": {
                feat: self.is_pro(feat)
                for feat in self.PRO_FEATURES
            },
            "open_features": [
                f for f in self.PRO_FEATURES
                if f not in self.PRO_FEATURES or self.is_pro(f)
            ],
        }

    def get_pro_features(self) -> dict:
        """Get all pro features and their status."""
        return {
            feat: {"description": desc, "available": self.is_pro(feat)}
            for feat, desc in self.PRO_FEATURES.items()
        }

    # ── Key Validation ─────────────────────────────────────────────

    def _validate_format(self, key: str) -> bool:
        """Validate license key format: WRAITH-XXXX-XXXX-XXXX."""
        parts = key.upper().split("-")
        if len(parts) != 4:
            return False
        if parts[0] != "WRAITH":
            return False
        for part in parts[1:]:
            if len(part) != 4 or not part.isalnum():
                return False
        return True

    def _validate_signature(self, key: str) -> bool:
        """
        Validate the key's signature.
        For now, accepts any properly formatted key.
        In production, this would verify against a signature.
        """
        # Simple validation: last segment is HMAC of first 3 segments
        # For demo/development, accept all valid-format keys
        return True

    def _get_license_type(self, key: str) -> str:
        """Determine license type from key prefix."""
        second_part = key.upper().split("-")[1] if "-" in key else ""
        if second_part.startswith("PRO"):
            return "pro"
        if second_part.startswith("ENT"):
            return "enterprise"
        return "open"

    def _mask_key(self, key: str) -> str:
        """Mask key for display: WRAITH-PRO-****-XXXX."""
        parts = key.upper().split("-")
        if len(parts) == 4:
            return f"{parts[0]}-{parts[1]}-****-{parts[3]}"
        return "****"

    @staticmethod
    def generate_trial_key() -> str:
        """Generate a 7-day trial pro key."""
        import secrets
        # Generate 4-char segments: PROX (pro trial) + 2 random segments
        pro_seg = "PRO" + secrets.token_hex(1).upper()[:1]  # 3+1=4 chars
        seg2 = secrets.token_hex(2).upper()  # 4 chars
        seg3 = secrets.token_hex(2).upper()  # 4 chars
        return f"WRAITH-{pro_seg}-{seg2}-{seg3}"

    def __repr__(self):
        status = "pro" if self.is_activated() else "open"
        return f"LicenseManager(status={status})"
