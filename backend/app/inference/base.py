"""推理后端抽象层。

设计要点：
- 所有后端（cloud / vllm / llama-cpp）都对外暴露 OpenAI 兼容的
  /v1/chat/completions 接口，因此适配器只需封装 HTTP 调用与鉴权差异。
- Llama-Guard-4 与 Prompt Guard 2 复用同一个抽象，只是 endpoint 不同。
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    role: str
    content: str


@dataclass
class ChatResult:
    """单次对话补全结果。"""

    text: str
    raw: dict
    latency_ms: int


class InferenceBackend(ABC):
    """推理后端接口：对一个模型端点做 OpenAI 兼容的 chat completion。"""

    name: str = "base"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout: float = 60.0,
        name: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        if name:
            self.name = name

    @abstractmethod
    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        max_tokens: int = 20,
        temperature: float = 0.0,
        extra: dict | None = None,
    ) -> ChatResult:
        """发起一次 chat completion。"""

    async def complete(
        self,
        prompt: str,
        *,
        max_tokens: int = 20,
        temperature: float = 0.0,
        stop: list[str] | None = None,
    ) -> ChatResult:
        """发起一次 raw prompt 补全（不经 chat template）。

        默认实现：回退到 chat（用单条 user 消息）。
        llama.cpp 后端会覆盖此方法走 /completion 端点。
        """
        return await self.chat(
            [ChatMessage(role="user", content=prompt)],
            max_tokens=max_tokens,
            temperature=temperature,
        )

    async def health(self) -> dict:
        """健康检查：默认探测 /v1/models。"""
        headers = self._auth_headers()
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/v1/models", headers=headers
                )
                ok = resp.status_code == 200
                return {
                    "status": "ok" if ok else "error",
                    "http": resp.status_code,
                    "model": self.model,
                    "endpoint": self.base_url,
                }
        except Exception as e:  # noqa: BLE001
            return {
                "status": "unreachable",
                "error": str(e),
                "model": self.model,
                "endpoint": self.base_url,
            }

    def _auth_headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key and self.api_key != "not-needed":
            h["Authorization"] = f"Bearer {self.api_key}"
        return h


# ---------------------------------------------------------------------------
# 具体适配器：三者仅 base_url/key/model 来源不同，chat 逻辑完全一致
# ---------------------------------------------------------------------------


class _OpenAICompatibleBackend(InferenceBackend):
    """通用 OpenAI 兼容 HTTP 后端（cloud / vllm / llama-cpp 共用）。"""

    async def chat(
        self,
        messages: list[ChatMessage],
        *,
        max_tokens: int = 20,
        temperature: float = 0.0,
        extra: dict | None = None,
    ) -> ChatResult:
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if extra:
            payload.update(extra)

        headers = self._auth_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return ChatResult(
            text=text or "",
            raw=data,
            latency_ms=int(
                data.get("usage", {}).get("total_latency_ms", 0) or 0
            ),
        )


class _LlamaCppBackend(_OpenAICompatibleBackend):
    """llama.cpp llama-server 专用后端。

    与通用后端的区别：支持 raw prompt 补全（/completion 端点），
    用于绕过有 bug 的 chat template（如 Llama-Guard-4 的 jinja 模板）。
    """

    async def complete(
        self,
        prompt: str,
        *,
        max_tokens: int = 20,
        temperature: float = 0.0,
        stop: list[str] | None = None,
    ) -> ChatResult:
        payload = {
            "prompt": prompt,
            "n_predict": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        if stop:
            payload["stop"] = stop

        headers = self._auth_headers()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/completion",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        text = data.get("content", "")
        return ChatResult(
            text=text or "",
            raw=data,
            latency_ms=int(data.get("timings", {}).get("predicted_ms", 0) or 0),
        )


def build_llama_guard_backend() -> InferenceBackend:
    """根据 INFERENCE_PROFILE 构造 Llama-Guard-4 后端。"""
    profile = settings.inference_profile
    if profile == "cloud":
        return _OpenAICompatibleBackend(
            base_url=settings.llama_guard_cloud_base_url,
            api_key=settings.llama_guard_cloud_api_key,
            model=settings.llama_guard_cloud_model,
            name="llama-guard-cloud",
        )
    if profile == "local-gpu":
        return _OpenAICompatibleBackend(
            base_url=settings.vllm_base_url,
            api_key=settings.vllm_api_key,
            model=settings.vllm_model,
            name="llama-guard-vllm",
        )
    # local-cpu（llama.cpp，用 /completion 端点绕过有 bug 的 chat template）
    return _LlamaCppBackend(
        base_url=settings.llama_cpp_base_url,
        api_key=settings.llama_cpp_api_key,
        model=settings.llama_cpp_model,
        timeout=120.0,
        name="llama-guard-llamacpp",
    )


def build_prompt_guard_backend() -> InferenceBackend | None:
    """构造 Prompt Guard 2 后端；off 模式返回 None。"""
    if settings.prompt_guard_backend == "off":
        return None
    return _OpenAICompatibleBackend(
        base_url=settings.prompt_guard_base_url,
        api_key=settings.prompt_guard_api_key,
        model=settings.prompt_guard_model,
        name="prompt-guard",
    )


def build_cross_verify_backend() -> InferenceBackend | None:
    """构造 L4 交叉验证后端（OpenAI Compatible 通用大模型）；off 模式返回 None。"""
    if settings.cross_verify_backend == "off":
        return None
    return _OpenAICompatibleBackend(
        base_url=settings.cross_verify_base_url,
        api_key=settings.cross_verify_api_key,
        model=settings.cross_verify_model,
        name="cross-verify",
    )


# 单例缓存（进程内）
_llama_guard: InferenceBackend | None = None
_prompt_guard: InferenceBackend | None = None
_cross_verify: InferenceBackend | None = None


def get_llama_guard_backend() -> InferenceBackend:
    global _llama_guard
    if _llama_guard is None:
        _llama_guard = build_llama_guard_backend()
    return _llama_guard


def get_prompt_guard_backend() -> InferenceBackend | None:
    global _prompt_guard
    if _prompt_guard is None:
        _prompt_guard = build_prompt_guard_backend()
    return _prompt_guard


def get_cross_verify_backend() -> InferenceBackend | None:
    global _cross_verify
    if _cross_verify is None:
        _cross_verify = build_cross_verify_backend()
    return _cross_verify
