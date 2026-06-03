"""
WRAITH Tier Manager — Free Tier Gamification & Psychology

Free tier is designed to:
1. Give enough value that people use it and love it
2. Create natural upgrade pressure through smart limits
3. Drive viral growth through invite mechanics
4. Prevent abuse while feeling generous

Psychology principles used:
- Scarcity: Limited scans create urgency
- Loss aversion: Bonus scans expire (use them or lose them)
- Social proof: Invite friends, both benefit
- Investment: The more they use it, the more they need it
- Reciprocity: Free value makes them want to pay it forward
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional


class TierManager:
    """
    Manages free tier limits, invite bonuses, and upgrade psychology.
    """

    # Free tier configuration
    FREE_SCANS_PER_DAY = 2          # Base: 2 scans per day
    FREE_SCAN_DAYS_PER_WEEK = 2     # Can only scan on 2 days per week
    FREE_MAX_QUEUE = 3              # Can queue up to 3 scans

    # Invite bonus configuration
    INVITE_BONUS_SCANS = 10         # Each invite gives +10 bonus scans
    INVITE_BONUS_EXPIRY_DAYS = 2    # Bonus expires in 2 days (urgency)
    INVITE_BONUS_SPREAD_MONTH = True  # OR can spread across month
    MAX_INVITE_BONUS = 50           # Cap on bonus scans at any time
    INVITE_VERIFY_SCAN_REQUIRED = True  # Invited user must scan once

    # Pro tier
    PRO_SCANS_PER_DAY = 999999      # Effectively unlimited
    PRO_SCAN_DAYS_PER_WEEK = 7      # Every day
    PRO_MAX_QUEUE = 100

    # Enterprise
    ENTERPRISE_SCANS = 999999
    ENTERPRISE_QUEUE = 999999

    TIERS = {
        "free": {
            "name": "Free",
            "price": 0,
            "scans_per_day": FREE_SCANS_PER_DAY,
            "scan_days_per_week": FREE_SCAN_DAYS_PER_WEEK,
            "max_queue": FREE_MAX_QUEUE,
            "agents": ["ghost", "specter", "scanner", "breach", "forge",
                       "mirror", "neuron", "ledger", "searcher", "commander"],
            "features": [
                "Basic scanning",
                "Markdown reports",
                "Community support",
                "Bring your own AI",
            ],
        },
        "pro": {
            "name": "Pro",
            "price": 49,
            "currency": "USD",
            "scans_per_day": PRO_SCANS_PER_DAY,
            "scan_days_per_week": PRO_SCAN_DAYS_PER_WEEK,
            "max_queue": PRO_MAX_QUEUE,
            "agents": ["ghost", "specter", "scanner", "breach", "forge",
                       "mirror", "neuron", "ledger", "searcher", "commander",
                       "phantom", "orchestrator", "sentinel"],
            "features": [
                "Unlimited scanning",
                "PDF reports",
                "Compliance mapping",
                "Dark web monitoring",
                "Continuous monitoring (SENTINEL)",
                "Hosted AI (no API key needed)",
                "Priority support",
                "Self-evolving memory",
                "Advanced sandbox/VM",
            ],
        },
        "enterprise": {
            "name": "Enterprise",
            "price": -1,  # Custom
            "scans_per_day": ENTERPRISE_SCANS,
            "scan_days_per_week": 7,
            "max_queue": ENTERPRISE_QUEUE,
            "agents": ["all"],
            "features": ["Everything in Pro", "White labeling", "Custom agents",
                         "SLA", "Dedicated support", "On-premise option"],
        },
    }

    def __init__(self, user_data: Dict[str, Any] = None):
        self.user_data = user_data or {}

    @property
    def tier(self) -> str:
        return self.user_data.get("tier", "free")

    @property
    def scans_today(self) -> int:
        return self.user_data.get("scans_today", 0)

    @property
    def scan_days_used_this_week(self) -> int:
        return self.user_data.get("scan_days_used_this_week", 0)

    @property
    def bonus_scans(self) -> int:
        return self.user_data.get("bonus_scans", 0)

    @property
    def bonus_expiry(self) -> Optional[str]:
        return self.user_data.get("bonus_expiry")

    def get_daily_limit(self) -> int:
        """Get the daily scan limit including bonuses."""
        base = self.TIERS[self.tier]["scans_per_day"]
        if self.tier == "free":
            # Check if bonus scans are still valid
            bonus = self._get_valid_bonus_scans()
            return base + bonus
        return base

    def _get_valid_bonus_scans(self) -> int:
        """Get valid (non-expired) bonus scans."""
        if not self.bonus_scans or not self.bonus_expiry:
            return 0
        try:
            expiry = datetime.fromisoformat(self.bonus_expiry)
            if datetime.now() > expiry:
                return 0  # Expired
            return self.bonus_scans
        except (ValueError, TypeError):
            return 0

    def can_scan(self) -> Dict[str, Any]:
        """
        Check if the user can perform a scan.
        Returns a detailed response for UI display.
        """
        tier_config = self.TIERS[self.tier]

        # Pro/Enterprise: always can scan
        if self.tier in ("pro", "enterprise"):
            return {
                "can_scan": True,
                "reason": "unlimited",
                "scans_remaining": 999999,
                "tier": self.tier,
            }

        # Free tier checks
        # 1. Check scan days per week
        if self.scan_days_used_this_week >= tier_config["scan_days_per_week"]:
            # Check if they have bonus scans that extend their days
            bonus = self._get_valid_bonus_scans()
            if bonus <= 0:
                return {
                    "can_scan": False,
                    "reason": "weekly_limit",
                    "message": f"You've used your {tier_config['scan_days_per_week']} scan days this week.",
                    "upgrade_hint": "Invite friends for +10 bonus scans, or upgrade to Pro for unlimited scanning.",
                    "scans_remaining": 0,
                    "tier": self.tier,
                    "next_reset": self._get_next_week_reset(),
                }

        # 2. Check daily limit
        daily_limit = self.get_daily_limit()
        if self.scans_today >= daily_limit:
            bonus = self._get_valid_bonus_scans()
            if bonus > 0:
                return {
                    "can_scan": False,
                    "reason": "daily_limit_with_bonus",
                    "message": f"You've used all {daily_limit} scans today (including {bonus} bonus).",
                    "upgrade_hint": "Your bonus scans expire soon! Use them or invite more friends.",
                    "scans_remaining": 0,
                    "tier": self.tier,
                    "bonus_expiry": self.bonus_expiry,
                    "next_reset": self._get_next_day_reset(),
                }
            return {
                "can_scan": False,
                "reason": "daily_limit",
                "message": f"You've used all {self.FREE_SCANS_PER_DAY} free scans today.",
                "upgrade_hint": "Invite a friend for +10 bonus scans, or upgrade to Pro.",
                "scans_remaining": 0,
                "tier": self.tier,
                "next_reset": self._get_next_day_reset(),
            }

        remaining = daily_limit - self.scans_today
        return {
            "can_scan": True,
            "reason": "ok",
            "scans_remaining": remaining,
            "tier": self.tier,
            "bonus_scans_available": self._get_valid_bonus_scans(),
            "bonus_expiry": self.bonus_expiry,
            "scan_days_remaining": tier_config["scan_days_per_week"] - self.scan_days_used_this_week,
        }

    def record_scan(self) -> Dict[str, Any]:
        """Record that a user performed a scan."""
        self.user_data["scans_today"] = self.scans_today + 1
        self.user_data["scan_days_used_this_week"] = self.scan_days_used_this_week + 1
        self.user_data["total_scans"] = self.user_data.get("total_scans", 0) + 1
        self.user_data["last_scan_at"] = datetime.now().isoformat()

        # Check if they're approaching limits (for upgrade nudges)
        result = self.can_scan()
        result["just_scanned"] = True
        result["total_scans"] = self.user_data["total_scans"]

        # Upgrade nudge logic
        if self.tier == "free":
            if self.user_data["total_scans"] == 3:
                result["nudge"] = "You're getting the hang of WRAITH! 🔥 Unlock unlimited scans with Pro."
            elif self.user_data["total_scans"] == 10:
                result["nudge"] = "You've done 10 scans! You're a power user. Pro would save you time. 💪"
            elif not result["can_scan"] and result["reason"] == "daily_limit":
                result["nudge"] = "You've hit your daily limit. Pro users scan unlimited. 🚀"

        return result

    def add_invite_bonus(self, count: int = 1, spread_month: bool = False) -> Dict[str, Any]:
        """Add bonus scans from invites."""
        current_bonus = self._get_valid_bonus_scans()
        new_bonus = min(current_bonus + (count * self.INVITE_BONUS_SCANS), self.MAX_INVITE_BONUS)

        if spread_month:
            expiry = datetime.now() + timedelta(days=30)
        else:
            expiry = datetime.now() + timedelta(days=self.INVITE_BONUS_EXPIRY_DAYS)

        self.user_data["bonus_scans"] = new_bonus
        self.user_data["bonus_expiry"] = expiry.isoformat()
        self.user_data["total_invites"] = self.user_data.get("total_invites", 0) + count

        return {
            "bonus_added": count * self.INVITE_BONUS_SCANS,
            "total_bonus": new_bonus,
            "expires_at": expiry.isoformat(),
            "expiry_days": 30 if spread_month else self.INVITE_BONUS_EXPIRY_DAYS,
            "message": f"🎉 +{count * self.INVITE_BONUS_SCANS} bonus scans! Use them before {expiry.strftime('%b %d')}.",
        }

    def get_tier_comparison(self) -> Dict[str, Any]:
        """Get a comparison of all tiers (for pricing page)."""
        return {
            "tiers": self.TIERS,
            "current_tier": self.tier,
            "usage": {
                "scans_today": self.scans_today,
                "daily_limit": self.get_daily_limit(),
                "scan_days_used": self.scan_days_used_this_week,
                "bonus_scans": self._get_valid_bonus_scans(),
                "total_scans": self.user_data.get("total_scans", 0),
                "total_invites": self.user_data.get("total_invites", 0),
            },
        }

    def get_upgrade_nudge(self) -> Optional[str]:
        """Get a contextual upgrade message based on usage patterns."""
        if self.tier != "free":
            return None

        total = self.user_data.get("total_scans", 0)
        days_used = self.user_data.get("scan_days_used_this_week", 0)

        if total == 0:
            return None
        elif total <= 3:
            return "🔥 You're just getting started! Pro gives you unlimited scans."
        elif days_used >= self.FREE_SCAN_DAYS_PER_WEEK:
            return "⚡ You've hit your weekly limit. Pro scans every day, unlimited."
        elif self.scans_today >= self.FREE_SCANS_PER_DAY:
            return "🚀 Daily limit reached. Pro users never see this message."
        elif total >= 20:
            return "💪 You're a power user! You'd save hours with Pro. $49/month."
        return None

    def _get_next_day_reset(self) -> str:
        """Get the next day reset time."""
        tomorrow = datetime.now() + timedelta(days=1)
        return tomorrow.replace(hour=0, minute=0, second=0).isoformat()

    def _get_next_week_reset(self) -> str:
        """Get the next week reset time."""
        days_until_monday = (7 - datetime.now().weekday()) % 7
        if days_until_monday == 0:
            days_until_monday = 7
        next_monday = datetime.now() + timedelta(days=days_until_monday)
        return next_monday.replace(hour=0, minute=0, second=0).isoformat()

    @classmethod
    def get_pricing_page_data(cls) -> Dict[str, Any]:
        """Get data for the pricing/landing page."""
        return {
            "tiers": cls.TIERS,
            "highlights": {
                "free": ["2 scans/day", "2 days/week", "9 agents", "Community support"],
                "pro": ["Unlimited scans", "Every day", "13 agents", "Hosted AI",
                        "PDF reports", "Dark web monitoring", "SENTINEL agent"],
                "enterprise": ["Everything in Pro", "White label", "Custom agents",
                               "SLA", "On-premise"],
            },
            "faq": [
                {
                    "q": "Can I use WRAITH for free?",
                    "a": "Yes! 2 scans per day, 2 days per week. Invite friends for +10 bonus scans each."
                },
                {
                    "q": "What happens when I hit my limit?",
                    "a": "You can invite friends for bonus scans, or upgrade to Pro for unlimited."
                },
                {
                    "q": "Do bonus scans expire?",
                    "a": "Yes — 2 days by default, or spread across a month. Use them or lose them!"
                },
                {
                    "q": "Can I cancel Pro anytime?",
                    "a": "Yes. You keep Pro access until the end of your billing period."
                },
                {
                    "q": "What AI model does Pro use?",
                    "a": "Pro uses our hosted AI (powered by OpenRouter). No API key needed."
                },
            ],
        }
