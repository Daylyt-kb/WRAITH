"""
ScopeValidator — Cryptographic Scope Enforcement
The legal heart of WRAITH. Every action passes through this gate.
If a target is not in scope, it is BLOCKED — not warned.

ConsentManager — Authorization Evidence System
Records and verifies user authorization for each target.
"""

import re
import json
import hashlib
import ipaddress
from datetime import datetime
from pathlib import Path


class ScopeValidator:
    """
    Validates that every action stays within the authorized scope.
    This is architecture-level enforcement, not a checkbox.
    """

    def __init__(self, target: str = "", scope_file: str = None):
        self.targets = []
        self.scope_hash = ""

        if target:
            self.add_target(target)

        if scope_file:
            self.load_scope_file(scope_file)

    def add_target(self, target: str):
        """Add a target to the authorized scope."""
        clean = self._normalize_target(target)
        if clean not in self.targets:
            self.targets.append(clean)
        self.scope_hash = self._hash_scope()

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target is within the authorized scope.
        Returns True only if explicitly authorized.
        """
        if not self.targets:
            return False

        clean = self._normalize_target(target)

        for authorized in self.targets:
            # Exact match
            if clean == authorized:
                return True
            # Subdomain of authorized domain
            if clean.endswith(f".{authorized}"):
                return True
            # IP in authorized CIDR range
            try:
                net = ipaddress.ip_network(authorized, strict=False)
                addr = ipaddress.ip_address(clean)
                if addr in net:
                    return True
            except ValueError:
                pass

        return False

    def assert_in_scope(self, target: str):
        """Hard gate — raises exception if target is not in scope."""
        if not self.is_in_scope(target):
            raise PermissionError(
                f"SCOPE VIOLATION: '{target}' is not in the authorized scope.\n"
                f"Authorized targets: {self.targets}\n"
                f"WRAITH will not proceed. Add this target to your scope document."
            )

    def load_scope_file(self, path: str):
        """Load scope from a JSON file."""
        try:
            with open(path) as f:
                data = json.load(f)
            for t in data.get("targets", []):
                self.add_target(t)
        except Exception as e:
            raise ValueError(f"Could not load scope file: {e}")

    def _normalize_target(self, target: str) -> str:
        """Normalize a target string. Preserves CIDR notation."""
        t = target.lower().strip()
        t = t.replace("https://", "").replace("http://", "")
        # Preserve CIDR (e.g. 192.168.1.0/24) — only strip path for non-CIDR
        import re
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$', t):
            return t  # CIDR range — return as-is
        t = t.split("/")[0].split("?")[0].split(":")[0]
        return t

    def _hash_scope(self) -> str:
        """Create a cryptographic hash of the current scope."""
        scope_str = json.dumps(sorted(self.targets))
        return hashlib.sha256(scope_str.encode()).hexdigest()[:16]

    def get_scope_token(self) -> str:
        """Return a scope token for audit trail."""
        return f"SCOPE-{self.scope_hash}-{datetime.now().strftime('%Y%m%d')}"


class ConsentManager:
    """
    Records user authorization for each target.
    Creates an audit trail of consent evidence.
    """

    def __init__(self, consent_dir: str = "./wraith_output/consent"):
        self.consent_dir = Path(consent_dir)
        self.consent_dir.mkdir(parents=True, exist_ok=True)

    def record_consent(
        self,
        target: str,
        user_id: str = "local_user",
        authorization_type: str = "owner",
        notes: str = ""
    ) -> str:
        """
        Record that the user has authorized testing of this target.
        Returns a consent token for the audit trail.
        """
        timestamp = datetime.now().isoformat()
        consent_id = hashlib.sha256(
            f"{target}{user_id}{timestamp}".encode()
        ).hexdigest()[:12]

        record = {
            "consent_id": consent_id,
            "target": target,
            "user_id": user_id,
            "authorization_type": authorization_type,
            "timestamp": timestamp,
            "notes": notes,
            "ip_acknowledged": True,
            "legal_acknowledgment": (
                "User confirms they own or have written authorization to test this target. "
                "Unauthorized testing is illegal under the CFAA and equivalent laws."
            )
        }

        # Save consent record
        consent_file = self.consent_dir / f"consent_{consent_id}.json"
        with open(consent_file, "w") as f:
            json.dump(record, f, indent=2)

        return consent_id

    def verify_consent(self, target: str) -> bool:
        """Check if we have a consent record for this target."""
        target_clean = target.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]

        for consent_file in self.consent_dir.glob("consent_*.json"):
            try:
                with open(consent_file) as f:
                    record = json.load(f)
                recorded_target = record.get("target", "").lower().strip()
                if recorded_target == target_clean or target_clean.endswith(f".{recorded_target}"):
                    return True
            except Exception:
                pass
        return False

    def interactive_consent(self, target: str) -> bool:
        """
        Interactive consent flow for CLI usage.
        Returns True only if user explicitly confirms authorization.
        """
        print("\n" + "="*60)
        print("WRAITH — AUTHORIZATION GATE")
        print("="*60)
        print(f"Target: {target}")
        print()
        print("Before WRAITH can test this target, you must confirm:")
        print("  1. You OWN this system, OR")
        print("  2. You have WRITTEN PERMISSION from the owner")
        print()
        print("Unauthorized testing is ILLEGAL under:")
        print("  - Computer Fraud & Abuse Act (CFAA) — USA")
        print("  - Computer Misuse Act — UK")
        print("  - Similar laws in most countries")
        print()

        answer = input("Do you have authorization to test this target? (yes/no): ").strip().lower()

        if answer != "yes":
            print("\n⚠ Authorization not confirmed. WRAITH will not proceed.")
            print("Only test systems you own or have explicit permission to test.")
            return False

        auth_type = input("Authorization type (owner/bugbounty/pentest_contract): ").strip() or "owner"
        notes = input("Optional notes (e.g. 'My personal VPS' or 'HackerOne program'): ").strip()

        consent_id = self.record_consent(target, authorization_type=auth_type, notes=notes)
        print(f"\n✓ Authorization recorded. Consent ID: {consent_id}")
        print(f"  Saved to: {self.consent_dir}/consent_{consent_id}.json\n")
        return True
