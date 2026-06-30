"""Concrete LLM providers. SDKs are imported lazily so Specter installs light."""
from __future__ import annotations

import json

import httpx

from specter.llm.base import LLMClient, LLMResponse


class AnthropicClient(LLMClient):
    provider = "anthropic"

    def chat(self, messages, max_tokens=2048, temperature=0.2) -> LLMResponse:
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pip install 'ai-specter[claude]' for Claude support") from e

        client = anthropic.Anthropic(api_key=self.api_key)
        system = "\n".join(m.content for m in messages if m.role == "system")
        convo = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]
        resp = client.messages.create(
            model=self.model,
            system=system or None,
            messages=convo,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return LLMResponse(
            text=text,
            provider=self.provider,
            model=self.model,
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
        )


class OpenAIClient(LLMClient):
    provider = "openai"

    def chat(self, messages, max_tokens=2048, temperature=0.2) -> LLMResponse:
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pip install 'ai-specter[openai]' for GPT support") from e

        client = OpenAI(api_key=self.api_key, base_url=self.base_url or None)
        resp = client.chat.completions.create(
            model=self.model,
            messages=[{"role": m.role, "content": m.content} for m in messages],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        usage = resp.usage
        return LLMResponse(
            text=resp.choices[0].message.content or "",
            provider=self.provider,
            model=self.model,
            input_tokens=getattr(usage, "prompt_tokens", 0),
            output_tokens=getattr(usage, "completion_tokens", 0),
        )


class OllamaClient(LLMClient):
    """Local models via the Ollama HTTP API — fully offline, no API key."""

    provider = "ollama"

    def chat(self, messages, max_tokens=2048, temperature=0.2) -> LLMResponse:
        url = (self.base_url or "http://localhost:11434").rstrip("/") + "/api/chat"
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        with httpx.Client(timeout=300) as client:
            r = client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
        return LLMResponse(
            text=data.get("message", {}).get("content", ""),
            provider=self.provider,
            model=self.model,
            input_tokens=data.get("prompt_eval_count", 0),
            output_tokens=data.get("eval_count", 0),
        )


class OpenAICompatibleClient(OpenAIClient):
    """Any OpenAI-compatible endpoint (Groq, Together, OpenRouter, vLLM, LM Studio)."""

    provider = "openai-compatible"


class AzureOpenAIClient(LLMClient):
    """Azure-hosted OpenAI deployments.

    ``base_url`` is the Azure resource endpoint (e.g.
    ``https://my-res.openai.azure.com``). ``model`` is the *deployment* name.
    The API version is read from ``AZURE_OPENAI_API_VERSION`` (default below).
    """

    provider = "azure-openai"
    default_api_version = "2024-06-01"

    def chat(self, messages, max_tokens=2048, temperature=0.2) -> LLMResponse:
        try:
            from openai import AzureOpenAI
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pip install 'ai-specter[openai]' for Azure OpenAI support") from e

        import os
        client = AzureOpenAI(
            api_key=self.api_key,
            azure_endpoint=self.base_url,
            api_version=os.environ.get("AZURE_OPENAI_API_VERSION", self.default_api_version),
        )
        resp = client.chat.completions.create(
            model=self.model,  # Azure deployment name
            messages=[{"role": m.role, "content": m.content} for m in messages],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        usage = resp.usage
        return LLMResponse(
            text=resp.choices[0].message.content or "",
            provider=self.provider,
            model=self.model,
            input_tokens=getattr(usage, "prompt_tokens", 0),
            output_tokens=getattr(usage, "completion_tokens", 0),
        )


class BedrockClient(LLMClient):
    """Amazon Bedrock via boto3 — IAM auth, no API key needed.

    Uses the Converse API so a single code path works across Anthropic, Llama,
    Mistral, Titan, and other Bedrock-hosted models. Region comes from the
    standard AWS env (``AWS_REGION``/``AWS_DEFAULT_REGION``) or ``base_url``.
    """

    provider = "bedrock"

    def chat(self, messages, max_tokens=2048, temperature=0.2) -> LLMResponse:
        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("pip install 'ai-specter[bedrock]' for Amazon Bedrock support") from e

        import os
        region = (self.base_url or os.environ.get("AWS_REGION")
                  or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1")
        client = boto3.client("bedrock-runtime", region_name=region)
        system = [{"text": m.content} for m in messages if m.role == "system"]
        convo = [{"role": m.role, "content": [{"text": m.content}]}
                 for m in messages if m.role != "system"]
        resp = client.converse(
            modelId=self.model,
            messages=convo,
            system=system or None,
            inferenceConfig={"maxTokens": max_tokens, "temperature": temperature},
        )
        text = "".join(b.get("text", "")
                       for b in resp["output"]["message"]["content"])
        usage = resp.get("usage", {})
        return LLMResponse(
            text=text,
            provider=self.provider,
            model=self.model,
            input_tokens=usage.get("inputTokens", 0),
            output_tokens=usage.get("outputTokens", 0),
        )


class MistralClient(OpenAIClient):
    """Mistral La Plateforme (OpenAI-compatible API; EU data residency)."""

    provider = "mistral"

    def __init__(self, model: str, api_key: str | None = None, base_url: str = "") -> None:
        super().__init__(model, api_key=api_key,
                         base_url=base_url or "https://api.mistral.ai/v1")


class VLLMClient(OpenAICompatibleClient):
    """Self-hosted vLLM OpenAI-compatible server (GPU-optimized)."""

    provider = "vllm"

    def __init__(self, model: str, api_key: str | None = None, base_url: str = "") -> None:
        super().__init__(model, api_key=api_key or "EMPTY",
                         base_url=base_url or "http://localhost:8000/v1")


class LMStudioClient(OpenAICompatibleClient):
    """LM Studio desktop local server (OpenAI-compatible, fully offline)."""

    provider = "lmstudio"

    def __init__(self, model: str, api_key: str | None = None, base_url: str = "") -> None:
        super().__init__(model, api_key=api_key or "lm-studio",
                         base_url=base_url or "http://localhost:1234/v1")


class EchoClient(LLMClient):
    """Offline stub so the engine runs end-to-end with zero credentials (demos/CI)."""

    provider = "echo"

    def chat(self, messages, max_tokens=2048, temperature=0.2) -> LLMResponse:
        user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        stub = {"note": "EchoClient stub — no live LLM configured", "echo": user[:280]}
        return LLMResponse(text=json.dumps(stub), provider=self.provider, model=self.model)


PROVIDER_CLASSES: dict[str, type[LLMClient]] = {
    "anthropic": AnthropicClient,
    "openai": OpenAIClient,
    "ollama": OllamaClient,
    "openai-compatible": OpenAICompatibleClient,
    "azure-openai": AzureOpenAIClient,
    "bedrock": BedrockClient,
    "mistral": MistralClient,
    "vllm": VLLMClient,
    "lmstudio": LMStudioClient,
    "echo": EchoClient,
}
