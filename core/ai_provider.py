"""
WRAITH Universal AI Provider
Supports: Anthropic Claude, Google Gemini, OpenAI, Mistral, Groq
Add your key in the dashboard — WRAITH picks the right SDK automatically.
No code changes needed when switching providers.
"""

import os
import json
import urllib.request
import urllib.error


# Registry of all supported providers
PROVIDERS = {
    "anthropic": {
        "name": "Anthropic Claude",
        "models": ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-6"],
        "default_model": "claude-sonnet-4-20250514",
        "env_key": "ANTHROPIC_API_KEY",
        "key_prefix": "sk-ant-",
        "docs": "https://console.anthropic.com",
        "free_tier": False,
    },
    "gemini": {
        "name": "Google Gemini",
        "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash"],
        "default_model": "gemini-1.5-flash",
        "env_key": "GEMINI_API_KEY",
        "key_prefix": "AIzaSy",
        "docs": "https://aistudio.google.com",
        "free_tier": True,
    },
    "openai": {
        "name": "OpenAI GPT",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
        "default_model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
        "key_prefix": "sk-",
        "docs": "https://platform.openai.com",
        "free_tier": False,
    },
    "groq": {
        "name": "Groq (Free + Fast)",
        "models": ["llama-3.3-70b-versatile", "mixtral-8x7b-32768", "gemma2-9b-it"],
        "default_model": "llama-3.3-70b-versatile",
        "env_key": "GROQ_API_KEY",
        "key_prefix": "gsk_",
        "docs": "https://console.groq.com",
        "free_tier": True,
    },
    "mistral": {
        "name": "Mistral AI",
        "models": ["mistral-large-latest", "mistral-small-latest", "open-mistral-7b"],
        "default_model": "mistral-small-latest",
        "env_key": "MISTRAL_API_KEY",
        "key_prefix": "MIST",
        "docs": "https://console.mistral.ai",
        "free_tier": False,
    },
    "openrouter": {
        "name": "OpenRouter",
        "models": ["openrouter/auto", "anthropic/claude-sonnet-4", "openai/gpt-4o",
                    "google/gemini-1.5-pro", "meta-llama/llama-3.1-70b-instruct"],
        "default_model": "openrouter/auto",
        "env_key": "OPENROUTER_API_KEY",
        "key_prefix": "sk-or-",
        "docs": "https://openrouter.ai/keys",
        "free_tier": True,
    },
}


class AIProvider:
    """
    Universal AI interface. Pass any API key and model — it routes automatically.
    """

    def __init__(self, api_key: str = "", provider: str = "", model: str = ""):
        self.api_key = api_key or self._detect_from_env()
        self.provider = provider or self._detect_provider(self.api_key)
        self.model = model or self._default_model()
        self._client = None

    # ── Public API ──────────────────────────────────────────────────────────

    def complete(self, prompt: str, system: str = "", max_tokens: int = 1000) -> str:
        """Send a prompt, get a response. Works for all providers."""
        if not self.api_key:
            return self._no_key_fallback(prompt)

        try:
            if self.provider == "anthropic":
                return self._anthropic(prompt, system, max_tokens)
            elif self.provider == "gemini":
                return self._gemini(prompt, system, max_tokens)
            elif self.provider == "openai":
                return self._openai(prompt, system, max_tokens)
            elif self.provider == "groq":
                return self._groq(prompt, system, max_tokens)
            elif self.provider == "mistral":
                return self._mistral(prompt, system, max_tokens)
            else:
                return self._openai_compat(prompt, system, max_tokens)
        except Exception as e:
            err = str(e)
            if "quota" in err.lower() or "credit" in err.lower() or "billing" in err.lower():
                return f"[AI] API key has no credits. Get free credits at {PROVIDERS.get(self.provider, {}).get('docs', '')}"
            return f"[AI] Provider error ({self.provider}): {err[:200]}"

    def is_configured(self) -> bool:
        return bool(self.api_key and self.provider)

    def status(self) -> dict:
        return {
            "configured": self.is_configured(),
            "provider": self.provider,
            "provider_name": PROVIDERS.get(self.provider, {}).get("name", "Unknown"),
            "model": self.model,
            "key_preview": f"{self.api_key[:8]}...{self.api_key[-4:]}" if self.api_key else "not set",
        }

    # ── Provider implementations ─────────────────────────────────────────────

    def _anthropic(self, prompt: str, system: str, max_tokens: int) -> str:
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        kwargs = {"model": self.model, "max_tokens": max_tokens,
                  "messages": [{"role": "user", "content": prompt}]}
        if system:
            kwargs["system"] = system
        r = client.messages.create(**kwargs)
        return r.content[0].text

    def _gemini(self, prompt: str, system: str, max_tokens: int) -> str:
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        model = genai.GenerativeModel(self.model)
        r = model.generate_content(
            full_prompt,
            generation_config=genai.GenerationConfig(max_output_tokens=max_tokens)
        )
        return r.text

    def _openai(self, prompt: str, system: str, max_tokens: int) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._openai_compat_call(
            "https://api.openai.com/v1/chat/completions",
            messages, max_tokens
        )

    def _groq(self, prompt: str, system: str, max_tokens: int) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._openai_compat_call(
            "https://api.groq.com/openai/v1/chat/completions",
            messages, max_tokens
        )

    def _mistral(self, prompt: str, system: str, max_tokens: int) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return self._openai_compat_call(
            "https://api.mistral.ai/v1/chat/completions",
            messages, max_tokens
        )

    def _openai_compat(self, prompt: str, system: str, max_tokens: int) -> str:
        """Generic OpenAI-compatible endpoint."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        default_url = "https://openrouter.ai/api/v1" if self.provider == "openrouter" else "https://api.openai.com/v1"
        base_url = os.environ.get("OPENAI_BASE_URL", default_url)
        return self._openai_compat_call(
            f"{base_url}/chat/completions", messages, max_tokens
        )

    def _openai_compat_call(self, url: str, messages: list, max_tokens: int) -> str:
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
        }).encode()
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    # ── Detection logic ───────────────────────────────────────────────────────

    def _detect_from_env(self) -> str:
        for provider, info in PROVIDERS.items():
            key = os.environ.get(info["env_key"], "")
            if key:
                return key
        return ""

    def _detect_provider(self, key: str) -> str:
        if not key:
            return ""
        for provider, info in PROVIDERS.items():
            if key.startswith(info["key_prefix"]):
                return provider
        # Check env vars for explicit provider
        for provider, info in PROVIDERS.items():
            env_key = os.environ.get(info["env_key"], "")
            if env_key and env_key == key:
                return provider
        return "openai"  # Default to OpenAI-compatible

    def _default_model(self) -> str:
        return PROVIDERS.get(self.provider, {}).get("default_model", "gpt-4o-mini")

    def _no_key_fallback(self, prompt: str) -> str:
        return (
            "[AI Brain: Offline] No API key configured. "
            "Add one in the dashboard Settings tab. "
            "Free options: Gemini (aistudio.google.com) or Groq (console.groq.com)"
        )

    @staticmethod
    def detect_from_key(key: str) -> str:
        """Given a raw API key string, detect which provider it belongs to."""
        key = key.strip()
        for provider, info in PROVIDERS.items():
            if key.startswith(info["key_prefix"]):
                return provider
        return "openai"

    @staticmethod
    def all_providers() -> dict:
        return PROVIDERS
