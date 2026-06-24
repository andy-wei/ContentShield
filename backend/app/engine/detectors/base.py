"""Detector 抽象基类。"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..result import DetectorResult


class BaseDetector(ABC):
    """所有检测层的基类。"""

    name: str = "base"

    @abstractmethod
    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        """对文本执行检测。"""

    async def warmup(self) -> None:
        """预热（加载模型/词库），默认空实现。"""

    async def shutdown(self) -> None:
        """清理资源，默认空实现。"""
