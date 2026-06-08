"""
WRAITH v2.0 — Enhanced Universal AI Provider
Extends the existing provider with Ollama, LM Studio, and async support.
Every agent can use a different model from a different provider.

Supports: Anthropic, OpenAI, Gemini, Groq, Mistral, Ollama, LM Studio, 
          Together AI, Perplexity, DeepSeek, any OpenAI-compatible API.
"""

import os
import json
import urllib.request
import urllib.error
from typing import Optional, List, Dict


# ── Extended provider registry ──────────────────────────────────────
PROVIDERS = {
    "anthropic": {
        "name": "Anthropic Claude",
        "models": ["claude-sonnet-4-20250514", "claude-haiku-4-5-20251001", "claude-opus-4-6",
                    "claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"],
        "default_model": "claude-sonnet-4-20250514",
        "env_key": "ANTHROPIC_API_KEY",
        "key_prefix": "sk-ant-",
        "docs": "https://console.anthropic.com",
        "free_tier": False,
    },
    "openai": {
        "name": "OpenAI GPT",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo",
                    "o1-preview", "o1-mini", "o3-mini"],
        "default_model": "gpt-4o-mini",
        "env_key": "OPENAI_API_KEY",
        "key_prefix": "sk-",
        "docs": "https://platform.openai.com",
        "free_tier": False,
    },
    "gemini": {
        "name": "Google Gemini",
        "models": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash",
                    "gemini-2.0-flash-lite"],
        "default_model": "gemini-1.5-flash",
        "env_key": "GEMINI_API_KEY",
        "key_prefix": "AIzaSy",
        "docs": "https://aistudio.google.com",
        "free_tier": True,
    },
    "groq": {
        "name": "Groq (Free + Ultra-Fast)",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile",
                    "mixtral-8x7b-32768", "gemma2-9b-it"],
        "default_model": "llama-3.3-70b-versatile",
        "env_key": "GROQ_API_KEY",
        "key_prefix": "gsk_",
        "docs": "https://console.groq.com",
        "free_tier": True,
    },
    "mistral": {
        "name": "Mistral AI",
        "models": ["mistral-large-latest", "mistral-small-latest", "open-mistral-7b",
                    "pixtral-12b"],
        "default_model": "mistral-small-latest",
        "env_key": "MISTRAL_API_KEY",
        "key_prefix": "MIST",
        "docs": "https://console.mistral.ai",
        "free_tier": False,
    },
    "ollama": {
        "name": "Ollama (Local / Offline)",
        "models": [],  # Dynamically populated
        "default_model": "llama3.1:70b",
        "env_key": "",
        "key_prefix": "",
        "base_env": "OLLAMA_HOST",
        "base_default": "http://localhost:11434",
        "docs": "https://ollama.ai",
        "free_tier": True,
        "offline": True,
    },
    "lmstudio": {
        "name": "LM Studio (Local)",
        "models": [],  # Dynamically populated
        "default_model": "local-model",
        "env_key": "",
        "key_prefix": "",
        "base_env": "LMSTUDIO_HOST",
        "base_default": "http://localhost:1234",
        "docs": "https://lmstudio.ai",
        "free_tier": True,
        "offline": True,
    },
    "together": {
        "name": "Together AI",
        "models": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1",
                    "deepseek-ai/DeepSeek-V3"],
        "default_model": "meta-llama/Llama-3-70b-chat-hf",
        "env_key": "TOGETHER_API_KEY",
        "key_prefix": "",
        "docs": "https://together.ai",
        "free_tier": True,
    },
    "deepseek": {
        "name": "DeepSeek",
        "models": ["deepseek-chat", "deepseek-coder", "deepseek-v3"],
        "default_model": "deepseek-chat",
        "env_key": "DEEPSEEK_API_KEY",
        "key_prefix": "sk-",
        "docs": "https://platform.deepseek.com",
        "free_tier": True,
    },
    "perplexity": {
        "name": "Perplexity (Sonar)",
        "models": ["sonar-pro", "sonar", "sonar-reasoning-pro"],
        "default_model": "sonar-pro",
        "env_key": "PERPLEXITY_API_KEY",
        "key_prefix": "pplx-",
        "docs": "https://perplexity.ai",
        "free_tier": False,
    },
    "openrouter": {
        "name": "OpenRouter",
        "models": ["openrouter/auto", "anthropic/claude-sonnet-4", "openai/gpt-4o",
                    "google/gemini-1.5-pro", "meta-llama/llama-3.1-70b-instruct",
                    "deepseek/deepseek-chat", "mistralai/mistral-large"],
        "default_model": "openrouter/auto",
        "env_key": "OPENROUTER_API_KEY",
        "key_prefix": "sk-or-",
        "base_env": "OPENROUTER_BASE_URL",
        "base_default": "https://openrouter.ai/api/v1",
        "docs": "https://openrouter.ai/keys",
        "free_tier": True,
    },
    "custom": {
        "name": "Custom OpenAI-Compatible",
        "models": ["custom"],
        "default_model": "custom",
        "env_key": "CUSTOM_API_KEY",
        "key_prefix": "",
        "base_env": "CUSTOM_API_URL",
        "base_default": "http://localhost:8080/v1",
        "docs": "",
        "free_tier": True,
    },
}


class AIProvider:
    """
    Universal AI interface for WRAITH v2.0.
    
    Works with any provider. Routes automatically.
    Each WRAITH agent can use a different provider/model.
    
    Usage:
        # Auto-detect from environment
        ai = AIProvider()
        
        # Explicit provider
        ai = AIProvider(provider="ollama", model="llama3.1:70b")
        
        # With API key
        ai = AIProvider(api_key="sk-...", provider="openai", model="gpt-4o")
        
        # Generate response
        response = ai.complete("Scan this target for open ports", system="You are GHOST...")
        
        # Stream response (for real-time UI)
        for chunk in ai.stream("Analyze these scan results", system="..."):
            print(chunk, end="", flush=True)
    """

    def __init__(self, api_key: str = "", provider: str = "", model: str = "",
                 base_url: str = ""):
        self.api_key = api_key or self._detect_from_env(provider)
        self.provider = provider or self._detect_provider(self.api_key, base_url)
        self.base_url = base_url or self._get_base_url()
        self.model = model or self._default_model()
        self._client = None

    # ── Public API ──────────────────────────────────────────────────

    def complete(self, prompt: str, system: str = "", max_tokens: int = 2000,
                 temperature: float = 0.7) -> str:
        """
        Send a prompt, get a complete response.
        Works identically for all providers.
        """
        if not self.api_key and not self._is_offline():
            return self._no_key_fallback()

        try:
            if self.provider == "anthropic":
                return self._anthropic(prompt, system, max_tokens, temperature)
            elif self.provider in ("openai", "groq", "mistral", "together",
                                    "deepseek", "perplexity", "openrouter", "custom"):
                return self._openai_compat(prompt, system, max_tokens, temperature)
            elif self.provider == "ollama":
                return self._ollama(prompt, system, max_tokens, temperature)
            elif self.provider == "lmstudio":
                return self._lmstudio(prompt, system, max_tokens, temperature)
            elif self.provider == "gemini":
                return self._gemini(prompt, system, max_tokens)
            else:
                return self._openai_compat(prompt, system, max_tokens, temperature)
        except Exception as e:
            err = str(e)
            if "quota" in err.lower() or "credit" in err.lower() or "billing" in err.lower():
                return f"[AI] No credits. Get free credits at: {PROVIDERS.get(self.provider, {}).get('docs', 'N/A')}"
            if "connection" in err.lower() and self._is_offline():
                return "[AI] Ollama/LM Studio not running. Start it or switch provider."
            return f"[AI] Provider error ({self.provider}): {err[:300]}"

    def complete_json(self, prompt: str, system: str = "",
                       max_tokens: int = 2000) -> dict:
        """
        Get a JSON response. Used for structured agent communication.
        """
        response = self.complete(
            prompt + "\n\nRespond ONLY with valid JSON. No markdown, no code fences.",
            system=system, max_tokens=max_tokens, temperature=0.1
        )
        # Try to extract JSON from response
        try:
            # Remove code fences if present
            cleaned = response.strip()
            for prefix in ("```json", "```"):
                if cleaned.startswith(prefix):
                    cleaned = cleaned[len(prefix):]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            return json.loads(cleaned.strip())
        except json.JSONDecodeError:
            return {"raw_response": response, "parse_error": True}

    def stream(self, prompt: str, system: str = "", max_tokens: int = 2000):
        """
        Stream response tokens. For real-time web UI.
        Yields chunks of text as they arrive.
        """
        # Streaming works with OpenAI-compatible APIs and Ollama
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        url, headers, body = self._build_request(messages, max_tokens, stream=True)

        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=120) as resp:
                for line in resp:
                    line = line.decode("utf-8").strip()
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            return
                        try:
                            chunk = json.loads(data)
                            delta = chunk.get("choices", [{}])[0].get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                yield content
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            yield f"[AI Stream Error: {str(e)[:200]}]"

    def is_configured(self) -> bool:
        """Check if this provider is ready to use."""
        if self._is_offline():
            return True  # Ollama/LM Studio don't need keys
        return bool(self.api_key and self.provider)

    def status(self) -> dict:
        """Get provider status for dashboard display."""
        return {
            "configured": self.is_configured(),
            "provider": self.provider,
            "provider_name": PROVIDERS.get(self.provider, {}).get("name", "Unknown"),
            "model": self.model,
            "base_url": self.base_url,
            "key_preview": f"{self.api_key[:8]}...{self.api_key[-4:]}" if self.api_key else "not set",
            "offline": self._is_offline(),
        }

    def list_models(self) -> list:
        """List available models for this provider."""
        if self.provider == "ollama":
            return self._ollama_list_models()
        if self.provider == "lmstudio":
            return self._lmstudio_list_models()
        return PROVIDERS.get(self.provider, {}).get("models", [])

    # ── Provider Implementations ────────────────────────────────────

    def _anthropic(self, prompt, system, max_tokens, temperature):
        """Anthropic Claude API."""
        import anthropic
        client = anthropic.Anthropic(api_key=self.api_key)
        kwargs = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        r = client.messages.create(**kwargs)
        return r.content[0].text

    def _openai_compat(self, prompt, system, max_tokens, temperature):
        """Generic OpenAI-compatible API (OpenAI, Groq, Mistral, Together, DeepSeek, Perplexity)."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        url = f"{self.base_url}/chat/completions"
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        # Perplexity needs different header
        if self.provider == "perplexity":
            url = "https://api.perplexity.ai/chat/completions"

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _ollama(self, prompt, system, max_tokens, temperature):
        """Ollama local API — works fully offline."""
        url = f"{self.base_url}/api/generate"
        body = json.dumps({
            "model": self.model,
            "prompt": f"{system}\n\n{prompt}" if system else prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }).encode()
        headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
        return data.get("response", "")

    def _ollama_list_models(self) -> list:
        """List locally installed Ollama models."""
        try:
            url = f"{self.base_url}/api/tags"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return PROVIDERS["ollama"]["models"]

    def _lmstudio(self, prompt, system, max_tokens, temperature):
        """LM Studio local API — OpenAI-compatible."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        url = f"{self.base_url}/v1/chat/completions"
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }).encode()
        headers = {"Content-Type": "application/json", "Authorization": "Bearer lm-studio"}
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _lmstudio_list_models(self) -> list:
        """List LM Studio loaded models."""
        try:
            url = f"{self.base_url}/v1/models"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            return [m["id"] for m in data.get("data", [])]
        except Exception:
            return []

    def _gemini(self, prompt, system, max_tokens):
        """Google Gemini API."""
        import google.generativeai as genai
        genai.configure(api_key=self.api_key)
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        model = genai.GenerativeModel(self.model)
        r = model.generate_content(
            full_prompt,
            generation_config=genai.GenerationConfig(max_output_tokens=max_tokens)
        )
        return r.text

    # ── Helpers ─────────────────────────────────────────────────────

    def _is_offline(self) -> bool:
        return self.provider in ("ollama", "lmstudio")

    def _detect_from_env(self, preferred: str = "") -> str:
        if preferred:
            info = PROVIDERS.get(preferred, {})
            key = os.environ.get(info.get("env_key", ""), "")
            if key:
                return key
        for provider, info in PROVIDERS.items():
            key = os.environ.get(info.get("env_key", ""), "")
            if key:
                return key
        return ""

    def _detect_provider(self, key: str, base_url: str = "") -> str:
        if not key and not base_url:
            # Check for offline providers
            if os.environ.get("OLLAMA_HOST") or os.path.exists("/usr/local/bin/ollama"):
                return "ollama"
            return ""
        if base_url:
            return "custom"
        for provider, info in PROVIDERS.items():
            prefix = info.get("key_prefix", "")
            if prefix and key.startswith(prefix):
                return provider
        return "custom"

    def _get_base_url(self) -> str:
        provider_info = PROVIDERS.get(self.provider, {})
        if self.provider == "ollama":
            return os.environ.get("OLLAMA_HOST", provider_info.get("base_default", "http://localhost:11434"))
        if self.provider == "lmstudio":
            return os.environ.get("LMSTUDIO_HOST", provider_info.get("base_default", "http://localhost:1234"))
        base = provider_info.get("base_default", "")
        env_key = provider_info.get("base_env", "")
        if env_key:
            return os.environ.get(env_key, base)
        return base

    def _default_model(self) -> str:
        return PROVIDERS.get(self.provider, {}).get("default_model", "gpt-4o-mini")

    def _no_key_fallback(self) -> str:
        providers_list = []
        for pid, info in PROVIDERS.items():
            if info.get("free_tier"):
                providers_list.append(f"  • {info['name']} ({info.get('docs', '')})")
        return (
            "[AI Brain: Offline] No API key configured.\n"
            "Free options:\n" + "\n".join(providers_list) +
            "\n\nOr run fully offline with Ollama: ollama pull llama3.1"
        )

    @staticmethod
    def detect_from_key(key: str) -> str:
        for provider, info in PROVIDERS.items():
            if key.startswith(info.get("key_prefix", "x")):
                return provider
        return "openai"

    @staticmethod
    def all_providers() -> dict:
        return PROVIDERS

    def _build_request(self, messages, max_tokens, stream=False):
        """Build OpenAI-compatible request."""
        url = f"{self.base_url}/chat/completions"
        body = json.dumps({
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": stream,
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        return url, headers, body
