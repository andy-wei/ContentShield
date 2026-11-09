"""目标模型客户端：向待测 LLM 发送攻击 prompt，获取回复。

复用 _OpenAICompatibleBackend（与推理后端共用）。
"""

from __future__ import annotations

import logging

from ..inference.base import ChatMessage, _OpenAICompatibleBackend

logger = logging.getLogger(__name__)


class TargetClient:
    """待测目标模型的客户端。

    本质是对 _OpenAICompatibleBackend 的薄封装，
    把攻击 prompt 发给目标模型，拿到回复。
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 512,
        timeout: float = 60.0,
    ):
        self.backend = _OpenAICompatibleBackend(
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout=timeout,
            name="redteam-target",
        )
        self.temperature = temperature
        self.max_tokens = max_tokens

    async def attack(self, prompt: str) -> tuple[str | None, int]:
        """发送攻击 prompt，返回 (回复文本, 延迟毫秒)。

        请求失败返回 (None, 0)——错误信息由调用方记入 AttackResult.error，
        不能以错误文本冒充模型回复（会被 judge 误判为"安全拒绝"污染统计与导出）。
        """
        try:
            result = await self.backend.chat(
                [ChatMessage(role="user", content=prompt)],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )
            return result.text, result.latency_ms
        except Exception as e:  # noqa: BLE001
            logger.warning("目标模型请求失败: %s", e)
            return None, 0

    async def health(self) -> dict:
        """检查目标模型是否可达。"""
        return await self.backend.health()
