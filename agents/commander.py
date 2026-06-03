"""
COMMANDER — Master Orchestration Brain
Understands plain English. Delegates to specialist agents.
Now powered by the universal AI provider — works with
Anthropic, Gemini, OpenAI, Groq, Mistral, or no key at all.
"""

import os
import re
import json
from datetime import datetime
from agents.base import WraithAgent


SYSTEM_PROMPT = """You are WRAITH's Commander — an elite AI security orchestration brain.

Your job:
1. Parse the user's plain English security request
2. Identify the target, the intent, and the required agents
3. Validate that the request is legal (authorized testing only)
4. Return a structured mission plan as JSON

You are legal-by-design. You REFUSE to help with:
- Scanning systems without authorization
- Creating malware or ransomware
- Attacking critical infrastructure
- Any request that is clearly illegal

For every valid request, respond with a JSON mission plan:
{
  "valid": true/false,
  "reason": "why valid or invalid",
  "target": "extracted target",
  "intent": "what the user wants",
  "agents": ["ghost", "specter", "scanner"],
  "mode": "recon|osint|scan|full",
  "plain_english_summary": "what WRAITH will do in 2 sentences"
}

If the user is having a conversation (not requesting a scan), respond naturally as a security expert.
"""


class Commander(WraithAgent):
    name = "commander"
    version = "2.0.0"
    description = "Brain — understands you and orchestrates everything"
    category = "orchestration"
    tools = []
    sandbox_profile = None
    risk_level = "low"

    def __init__(self, api_key: str = "", provider: str = "", model: str = "", **kwargs):
        super().__init__(api_key=api_key, **kwargs)
        self.provider = provider
        self.model = model
        self.history = []
        self.last_mission = None
        self._ai = None

    def _get_ai(self):
        """Lazy-load the universal AI provider."""
        if self._ai is None:
            try:
                from core.ai_provider import AIProvider
                self._ai = AIProvider(self.api_key, self.provider, self.model)
            except ImportError:
                self._ai = None
        return self._ai

    def process(self, user_input: str, agents: dict, bus) -> str:
        """
        Process a plain English request.
        Uses universal AI provider — works with any configured key.
        """
        self.history.append({"role": "user", "content": user_input})

        ai = self._get_ai()
        if ai and ai.is_configured():
            response = self._universal_ai_process(user_input, agents, bus, ai)
        else:
            response = self._rule_process(user_input, agents, bus)

        self.history.append({"role": "assistant", "content": response})
        return response

    def _universal_ai_process(self, user_input: str, agents: dict, bus, ai) -> str:
        """Use the universal AI provider to understand and plan the mission."""
        try:
            text = ai.complete(
                prompt=f"User Request: {user_input}",
                system=SYSTEM_PROMPT,
                max_tokens=800
            )

            if text.startswith("[AI]"):
                # API error — fall back to rules
                return self._rule_process(user_input, agents, bus)

            # Try to parse as JSON mission plan
            try:
                plan = self._extract_json(text)
                if plan and plan.get("valid"):
                    return self._execute_plan(plan, agents, bus)
                elif plan and not plan.get("valid"):
                    return f"I can't help with that: {plan.get('reason', 'unauthorized action')}"
            except Exception:
                pass

            # If not JSON, return the text directly (conversational)
            return text

        except Exception as e:
            return self._rule_process(user_input, agents, bus)

    def _gemini_process(self, user_input: str, agents: dict, bus, api_key: str) -> str:
        """Use Gemini API to understand and plan the mission."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-pro') # High-speed, high-context

            prompt = f"{SYSTEM_PROMPT}\n\nUser Request: {user_input}"
            response = model.generate_content(prompt)
            text = response.text

            # Try to parse as JSON mission plan
            try:
                plan = self._extract_json(text)
                if plan and plan.get("valid"):
                    return self._execute_plan(plan, agents, bus)
                elif plan and not plan.get("valid"):
                    return f"I can't help with that: {plan.get('reason', 'unauthorized action')}"
            except Exception:
                pass

            return text

        except Exception as e:
            return f"Gemini Error: {e}\n\n" + self._rule_process(user_input, agents, bus)

    def _ai_process(self, user_input: str, agents: dict, bus) -> str:
        """Use Claude API to understand and plan the mission."""
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)

            messages = [{"role": "user", "content": user_input}]

            response = client.messages.create(
                model="claude-3-5-sonnet-20240620",
                max_tokens=1000,
                system=SYSTEM_PROMPT,
                messages=messages
            )

            text = response.content[0].text

            # Try to parse as JSON mission plan
            try:
                plan = self._extract_json(text)
                if plan and plan.get("valid"):
                    return self._execute_plan(plan, agents, bus)
                elif plan and not plan.get("valid"):
                    return f"I can't help with that: {plan.get('reason', 'unauthorized action')}"
            except Exception:
                pass

            # If not JSON, return the text directly (conversational)
            return text

        except Exception as e:
            return self._rule_process(user_input, agents, bus)

    def _rule_process(self, user_input: str, agents: dict, bus) -> str:
        """
        Rule-based fallback when no API key is set.
        Understands common patterns without AI.
        """
        inp = user_input.lower().strip()

        # Detect intent
        scan_keywords = ["scan", "test", "check", "audit", "recon", "enumerate"]
        osint_keywords = ["osint", "intel", "information", "emails", "subdomains", "find"]
        vuln_keywords = ["vuln", "vulnerability", "cve", "exploit", "weakness"]
        forge_keywords = ["script", "write", "generate", "code", "create a"]

        # Extract target (domain/IP pattern)
        target = self._extract_target(user_input)

        if any(k in inp for k in forge_keywords):
            if "forge" in agents:
                return agents["forge"].generate_from_description(user_input)
            return "FORGE agent: I can write custom scripts. Provide more detail about what you need."

        if target:
            # Safety check
            if not self._basic_safety_check(user_input):
                return (
                    "⚠ I only assist with authorized security testing. "
                    "Please confirm you own or have permission to test this target."
                )

            if any(k in inp for k in osint_keywords):
                return self._dispatch_osint(target, agents, bus)
            elif any(k in inp for k in vuln_keywords):
                return self._dispatch_scan(target, agents, bus)
            elif any(k in inp for k in scan_keywords):
                return self._dispatch_recon(target, agents, bus)
            else:
                return (
                    f"I found target: {target}\n"
                    f"What would you like me to do? (recon / osint / scan / full)\n"
                    f"Example: 'run full scan on {target}'"
                )

        # Conversational fallbacks
        if any(w in inp for w in ("hello", "hi", "hey", "sup")):
            return (
                "Commander online. Tell me a target and what you want to know about it.\n"
                "Example: 'scan my website mysite.com' or 'osint check domain.com'\n"
                "Remember: only test systems you own or have authorization for."
            )

        if "help" in inp:
            return (
                "WRAITH Commands:\n"
                "  scan <target>     — Map ports, services, technologies\n"
                "  osint <target>    — Find emails, subdomains, leaks\n"
                "  full <target>     — Complete swarm recon + scan\n"
                "  forge <task>      — Generate a custom security script\n"
                "  report            — Generate report from last results\n\n"
                "I understand plain English — just tell me what you need."
            )

        if any(w in inp for w in ("what", "how", "explain", "tell me")):
            return (
                "I'm WRAITH Commander. I orchestrate a swarm of AI security agents.\n"
                "Give me a target (domain/IP you own) and I'll map its attack surface,\n"
                "find OSINT intelligence, scan for vulnerabilities, and write custom scripts.\n\n"
                "No API key set — running in local mode. Set ANTHROPIC_API_KEY for AI-powered analysis."
            )

        return (
            "I didn't catch that. Try:\n"
            "  'scan example.com'\n"
            "  'osint mycompany.com'\n"
            "  'forge a script to enumerate subdomains'\n"
            "  'help' for full command list"
        )

    def _execute_plan(self, plan: dict, agents: dict, bus) -> str:
        """Execute a parsed mission plan."""
        target = plan.get("target", "")
        mode = plan.get("mode", "recon")
        summary = plan.get("plain_english_summary", "")

        self.last_mission = plan

        response_lines = [
            f"Mission understood. {summary}",
            f"\nTarget: {target} | Mode: {mode}",
            f"Deploying agents: {', '.join(plan.get('agents', []))}",
            "",
        ]

        if "ghost" in plan.get("agents", []) and "ghost" in agents:
            result = agents["ghost"].run(target, None)
            response_lines.append(f"[GHOST] {result.get('summary', 'Recon complete')}")

        if "specter" in plan.get("agents", []) and "specter" in agents:
            result = agents["specter"].run(target, None)
            response_lines.append(f"[SPECTER] {result.get('summary', 'OSINT complete')}")

        if "scanner" in plan.get("agents", []) and "scanner" in agents:
            result = agents["scanner"].run(target, None)
            response_lines.append(f"[SCANNER] {result.get('summary', 'Scan complete')}")

        response_lines.append("\nRun 'report' to generate the full report.")
        return "\n".join(response_lines)

    def _dispatch_recon(self, target: str, agents: dict, bus) -> str:
        if "ghost" in agents:
            result = agents["ghost"].run(target, None)
            return f"[GHOST deployed on {target}]\n{result.get('summary', '')}"
        return f"GHOST agent not available. Run: wraith.py --target {target} --mode recon --authorized"

    def _dispatch_osint(self, target: str, agents: dict, bus) -> str:
        if "specter" in agents:
            result = agents["specter"].run(target, None)
            return f"[SPECTER deployed on {target}]\n{result.get('summary', '')}"
        return f"SPECTER agent not available. Run: wraith.py --target {target} --mode osint --authorized"

    def _dispatch_scan(self, target: str, agents: dict, bus) -> str:
        if "scanner" in agents:
            result = agents["scanner"].run(target, None)
            return f"[SCANNER deployed on {target}]\n{result.get('summary', '')}"
        return f"SCANNER agent not available. Run: wraith.py --target {target} --mode scan --authorized"

    def _extract_target(self, text: str) -> str:
        """Extract domain or IP from text."""
        # IP pattern
        ip = re.search(
            r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b', text
        )
        if ip:
            return ip.group()
        # Domain pattern
        domain = re.search(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            text
        )
        if domain:
            d = domain.group()
            # Skip common false positives
            if d not in ("e.g", "i.e", "etc.com"):
                return d
        return ""

    def _basic_safety_check(self, text: str) -> bool:
        """Basic check — refuse obviously malicious requests."""
        red_flags = [
            "without permission", "hack into", "break into",
            "ddos", "denial of service", "ransomware",
            "malware", "steal", "crack passwords for someone",
        ]
        t = text.lower()
        return not any(flag in t for flag in red_flags)

    def _extract_json(self, text: str) -> dict:
        """Extract JSON from AI response."""
        # Try direct parse
        try:
            return json.loads(text)
        except Exception:
            pass
        # Try to find JSON block
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
        return {}
