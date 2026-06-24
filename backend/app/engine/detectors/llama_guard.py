"""L2 Llama-Guard-4-12B 检测器：S1-S14 内容危害分类（核心层）。

按官方 <CATEGORIES> 提示词模板动态拼装（仅注入启用的类别 + 自定义描述），
调用推理后端的 /v1/chat/completions，解析 "safe" / "unsafe\\nS1,S7" 输出。

参考：
- https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-4/
- https://huggingface.co/meta-llama/Llama-Guard-4-12B
"""
from __future__ import annotations

import logging
import time

from sqlalchemy import select

from ...db import async_session
from ...inference.base import ChatMessage, get_llama_guard_backend
from ...models import CategoryRule
from ..result import DetectorHit, DetectorResult
from .base import BaseDetector

logger = logging.getLogger(__name__)

# Llama-Guard-4 官方提示词模板（内容部分）
_GUARD_TASK = """Task: Check if there is unsafe content in the {role_name} messages in conversations according our safety policy. The safety policy for the input messages is below:

<categories>
{categories_block}
</categories>

Question: Does the input messages violate the above principles? Your response must start with 'safe' or 'unsafe' and nothing else. If 'unsafe', on a new line list the violated categories as comma separated values in the format <S#>,<S#>."""

# Llama 4 原始 token 格式（用于 /completion 端点，绕过有 bug 的 chat template）
_LLAMA4_PROMPT_FMT = (
    "<|begin_of_text|>"
    "<|header_start|>user<|header_end|>\n\n"
    "{task}\n\nUser: {content}<|eot_id|>"
    "<|header_start|>assistant<|header_end|>\n\n"
)


class LlamaGuardDetector(BaseDetector):
    name = "llama_guard"

    def __init__(self) -> None:
        self._backend = None
        self._categories_cache: list[CategoryRule] | None = None

    async def warmup(self) -> None:
        try:
            self._backend = get_llama_guard_backend()
        except Exception as e:  # noqa: BLE001
            logger.warning("Llama-Guard backend unavailable: %s", e)
            self._backend = None
        await self._reload_categories()

    async def invalidate(self) -> None:
        self._categories_cache = None

    async def _reload_categories(self) -> None:
        async with async_session() as session:
            res = await session.execute(
                select(CategoryRule)
                .where(CategoryRule.enabled.is_(True))
                .where(CategoryRule.action != "off")
                .order_by(CategoryRule.order)
            )
            self._categories_cache = list(res.scalars().all())

    def _build_categories_block(self, categories: list[CategoryRule]) -> str:
        """构造类别块（Llama-Guard-4 标准 'S1: Description' 格式）。

        使用简短类别名而非完整描述。完整描述会让 prompt 过长（14 类约 3KB），
        导致某些 GGUF 转换版本在长上下文下输出不稳定。
        """
        lines = []
        for c in categories:
            # name 形如 "暴力犯罪 Violent Crimes"，取英文部分（Llama-Guard 用英文训练）
            parts = c.name.strip().split()
            english = " ".join(p for p in parts if all(ord(ch) < 128 for ch in p))
            label = english or c.name.strip()
            lines.append(f"{c.code}: {label}.")
        return "\n".join(lines)

    def _parse(self, text: str) -> tuple[bool, list[str]]:
        """解析 'safe' / 'unsafe\\nS1,S7' 输出。

        容错：某些 GGUF 转换版本输出不稳定，unsafe 后可能跟乱码或无类别代码。
        只要首词是 unsafe 就判定为命中；无法识别类别时用 S-unknown 兜底。
        """
        if not text:
            return False, []
        lines = text.strip().splitlines()
        verdict = lines[0].strip().lower()
        if not verdict.startswith("unsafe"):
            return False, []
        violated: list[str] = []
        # 尝试从所有行中提取 S# 类别代码
        for line in lines[1:]:
            for token in line.replace(" ", "").replace(",", " ").split():
                token = token.strip().upper()
                if token.startswith("S") and token[1:].isdigit():
                    violated.append(token)
        return True, violated

    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        result = DetectorResult(name=self.name)

        if self._backend is None:
            result.decision = "skipped"
            result.raw = {"reason": "backend unavailable"}
            return result

        if self._categories_cache is None:
            await self._reload_categories()

        categories = self._categories_cache or []
        if not categories:
            result.decision = "skipped"
            result.raw = {"reason": "no categories enabled"}
            return result

        role_name = "User" if source == "user_prompt" else "Agent"
        task = _GUARD_TASK.format(
            role_name=role_name,
            categories_block=self._build_categories_block(categories),
        )
        # 用 Llama 4 原始格式拼装 prompt（走 /completion 端点，绕过 chat template bug）
        prompt = _LLAMA4_PROMPT_FMT.format(task=task, content=text[:4000])

        t0 = time.perf_counter()
        try:
            # 优先用 raw completion（local profile）；cloud/vllm 回退到 chat
            if hasattr(self._backend, "complete"):
                chat_result = await self._backend.complete(
                    prompt,
                    max_tokens=20,
                    temperature=0.0,
                    stop=["<|eot_id|>", "\nUser:", "\nAgent:"],
                )
            else:
                chat_result = await self._backend.chat(
                    [
                        ChatMessage(role="user", content=task + "\n\nUser: " + text[:4000]),
                    ],
                    max_tokens=20,
                    temperature=0.0,
                )
        except Exception as e:  # noqa: BLE001
            logger.warning("Llama-Guard backend error: %s", e)
            result.decision = "skipped"
            result.raw = {"error": str(e)}
            result.latency_ms = int((time.perf_counter() - t0) * 1000)
            return result

        result.latency_ms = int((time.perf_counter() - t0) * 1000)
        unsafe, violated = self._parse(chat_result.text)

        if not unsafe:
            result.raw = {"output": chat_result.text, "verdict": "safe"}
            return result

        # 映射 violated 到配置的 action
        action_map = {c.code: c.action for c in categories}
        name_map = {c.code: c.name for c in categories}
        overall_action = "pass"

        # 兜底：判定 unsafe 但无法解析具体类别时，用 S-unknown 命中（block）
        if not violated:
            violated = ["S-unknown"]

        for code in violated:
            action = action_map.get(code, "block")
            if action == "off":
                continue
            result.hits.append(
                DetectorHit(
                    category=code,
                    snippet=text[:120],
                    score=1.0,
                    extra={"name": name_map.get(code, code), "action": action},
                )
            )
            if action == "block":
                overall_action = "block"
            elif action == "warn" and overall_action == "pass":
                overall_action = "warn"

        result.hit = bool(result.hits)
        result.decision = overall_action
        result.raw = {
            "output": chat_result.text,
            "verdict": "unsafe",
            "violated": violated,
        }
        return result
