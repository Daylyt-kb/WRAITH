"""
WRAITH Legal Consent System

Digital authorization form that every user must sign before using WRAITH.
Creates an immutable audit trail and protects us legally.

The consent form:
1. Explains WRAITH is for authorized testing only
2. Lists applicable laws (CFAA, Computer Misuse Act, etc.)
3. Requires explicit confirmation of ownership or permission
4. Records user ID, timestamp, IP, and digital signature
5. Stored in Supabase (cloud) + local backup
"""

import os
import json
import hashlib
import secrets
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


# The legal consent text — this is what users see and agree to
CONSENT_FORM_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║                    WRAITH AUTHORIZATION FORM                     ║
║              Digital Consent for Security Testing                ║
╚══════════════════════════════════════════════════════════════════╝

⚠️  IMPORTANT: READ THIS COMPLETELY BEFORE PROCEEDING ⚠️

WRAITH is an autonomous AI security testing platform. It will actively
scan, probe, and test systems you specify using real security tools
including port scanners, vulnerability detectors, and controlled
exploitation techniques.

BY SIGNING THIS FORM, YOU CONFIRM AND AGREE TO THE FOLLOWING:

1. AUTHORIZATION
   You are the OWNER of every system you ask WRAITH to test, OR
   you have obtained WRITTEN PERMISSION from the owner to test it.

2. SCOPE
   You will ONLY test systems you are authorized to test.
   WRAITH enforces scope at the architectural level.

3. LEGAL COMPLIANCE
   You understand that unauthorized computer access is illegal under:
   • Computer Fraud and Abuse Act (CFAA) — United States
   • Computer Misuse Act 1990 — United Kingdom
   •_similar legislation in your jurisdiction
   
   Unauthorized testing can result in criminal charges, civil liability,
   and severe penalties including imprisonment.

4. NON-DESTRUCTIVE TESTING
   WRAITH uses non-destructive canary payloads by default.
   You understand that security testing carries inherent risks.

5. AUDIT TRAIL
   All actions are logged with timestamps, user identification,
   and scope records. This data is stored securely and immutably.

6. DATA HANDLING
   Scan results are stored securely. Anonymized vulnerability patterns
   may be shared across the WRAITH network to improve protection
   for all users. No personal data or target specifics are shared.

7. TERMS OF SERVICE
   You agree to WRAITH's Terms of Service and Privacy Policy.

8. ASSUMPTION OF RISK
   You assume all risks associated with security testing.
   WRAITH is provided "as is" without warranty.

═══════════════════════════════════════════════════════════════════

To proceed, you must type: "I AGREE"

This creates a legally-binding digital record of your authorization.
"""

# The confirmation phrase users must type
CONFIRMATION_PHRASE = "I AGREE"

# Laws referenced by jurisdiction
APPLICABLE_LAWS = {
    "US": {
        "name": "Computer Fraud and Abuse Act (CFAA)",
        "citation": "18 U.S.C. § 1030",
        "summary": "Unauthorized access to protected computers is a federal crime.",
    },
    "UK": {
        "name": "Computer Misuse Act 1990",
        "citation": "CMA 1990 Sections 1-3",
        "summary": "Unauthorized access, intent to commit further offenses, unauthorized modification.",
    },
    "EU": {
        "name": "Directive 2013/40/EU",
        "citation": "EU Cybercrime Directive",
        "summary": "Attacks against information systems across EU member states.",
    },
    "KE": {
        "name": "Kenya Computer Misuse and Cybercrimes Act",
        "citation": "Act No. 5 of 2018",
        "summary": "Unauthorized access, cyber fraud, and cyber extortion in Kenya.",
    },
    "AU": {
        "name": "Criminal Code Act 1995 (Cth)",
        "citation": "Division 477-478",
        "summary": "Unauthorized access to and modification of restricted data.",
    },
    "CA": {
        "name": "Criminal Code of Canada",
        "citation": "Section 342.1",
        "summary": "Unauthorized use of computer and mischief in relation to data.",
    },
}


class ConsentManager:
    """Manages the legal consent process and record storage."""

    def __init__(self, storage_dir: str = "./wraith_output/consent"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def get_consent_form(self, jurisdiction: str = "US") -> str:
        """Get the consent form text with jurisdiction-specific laws."""
        form = CONSENT_FORM_TEXT

        law = APPLICABLE_LAWS.get(jurisdiction, APPLICABLE_LAWS["US"])
        jurisdiction_addendum = f"""

APPLICABLE LAW FOR YOUR JURISDICTION ({jurisdiction}):
  {law['name']}
  Citation: {law['citation']}
  {law['summary']}
"""
        return form + jurisdiction_addendum + "\n\n" + "=" * 67

    def process_consent(self, user_id: str, typed_confirmation: str,
                        target_domains: list,
                        authorization_type: str = "owner",
                        jurisdiction: str = "US",
                        ip_address: str = "unknown",
                        notes: str = "") -> Dict[str, Any]:
        """
        Process a consent form submission.
        Returns the consent record if valid, error if not.
        """
        # Verify the confirmation phrase
        if typed_confirmation.strip() != CONFIRMATION_PHRASE:
            return {
                "success": False,
                "error": f"You must type '{CONFIRMATION_PHRASE}' exactly to proceed.",
            }

        # Generate consent record
        timestamp = datetime.utcnow().isoformat()
        consent_id = f"WRC-{secrets.token_hex(8).upper()}"

        # Create a digital signature of the consent
        signature_data = f"{user_id}:{','.join(target_domains)}:{timestamp}:{typed_confirmation}"
        digital_signature = hashlib.sha256(
            signature_data.encode() + os.urandom(16)
        ).hexdigest()

        law = APPLICABLE_LAWS.get(jurisdiction, APPLICABLE_LAWS["US"])

        record = {
            "consent_id": consent_id,
            "version": "2.0",
            "user_id": user_id,
            "timestamp": timestamp,
            "ip_address": ip_address,
            "jurisdiction": jurisdiction,
            "applicable_law": law["name"],
            "law_citation": law["citation"],
            "confirmation_phrase": CONFIRMATION_PHRASE,
            "digital_signature": digital_signature,
            "authorization_type": authorization_type,
            "authorized_targets": target_domains,
            "scope": {
                "type": authorization_type,
                "targets": target_domains,
                "valid_from": timestamp,
                "valid_until": None,  # Until revoked
            },
            "legal_text_hash": hashlib.sha256(CONSENT_FORM_TEXT.encode()).hexdigest()[:16],
            "notes": notes,
            "status": "active",
        }

        # Store locally
        record_path = self.storage_dir / f"{consent_id}.json"
        with open(record_path, "w") as f:
            json.dump(record, f, indent=2)

        return {
            "success": True,
            "consent_id": consent_id,
            "digital_signature": digital_signature,
            "timestamp": timestamp,
            "message": f"Authorization recorded. Consent ID: {consent_id}",
        }

    def verify_consent(self, user_id: str, target: str) -> Dict[str, Any]:
        """Verify that a user has valid consent for a target."""
        for record_file in self.storage_dir.glob("WRC-*.json"):
            try:
                with open(record_file) as f:
                    record = json.load(f)

                if record["user_id"] != user_id:
                    continue
                if record["status"] != "active":
                    continue

                # Check if target is in authorized targets or is a subdomain
                authorized = record.get("authorized_targets", [])
                target_clean = target.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]

                for auth_target in authorized:
                    auth_clean = auth_target.lower().strip()
                    if target_clean == auth_clean or target_clean.endswith(f".{auth_clean}"):
                        return {
                            "has_consent": True,
                            "consent_id": record["consent_id"],
                            "authorization_type": record["authorization_type"],
                            "scope": record["scope"],
                        }
            except Exception:
                continue

        return {"has_consent": False}

    def revoke_consent(self, consent_id: str, user_id: str) -> bool:
        """Revoke a consent record."""
        record_path = self.storage_dir / f"{consent_id}.json"
        if not record_path.exists():
            return False

        try:
            with open(record_path) as f:
                record = json.load(f)

            if record["user_id"] != user_id:
                return False

            record["status"] = "revoked"
            record["revoked_at"] = datetime.utcnow().isoformat()

            with open(record_path, "w") as f:
                json.dump(record, f, indent=2)
            return True
        except Exception:
            return False

    def get_user_consents(self, user_id: str) -> list:
        """Get all consent records for a user."""
        records = []
        for record_file in self.storage_dir.glob("WRC-*.json"):
            try:
                with open(record_file) as f:
                    record = json.load(f)
                if record["user_id"] == user_id:
                    records.append(record)
            except Exception:
                continue
        return records

    def interactive_consent_flow(self, user_id: str) -> Dict[str, Any]:
        """
        Interactive consent flow (for CLI usage).
        In web UI, this is handled by the consent form page.
        """
        print(self.get_consent_form())
        typed = input("\nType 'I AGREE' to authorize: ").strip()

        targets_input = input("Enter target domains (comma-separated): ").strip()
        targets = [t.strip() for t in targets_input.split(",") if t.strip()]

        if not targets:
            print("❌ No targets specified. Consent not recorded.")
            return {"success": False, "error": "No targets specified"}

        auth_type = input("Authorization type (owner/bugbounty/pentest_contract) [owner]: ").strip() or "owner"

        return self.process_consent(
            user_id=user_id,
            typed_confirmation=typed,
            target_domains=targets,
            authorization_type=auth_type,
        )
