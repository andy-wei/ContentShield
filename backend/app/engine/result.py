"""检测结果数据结构（detector 内部用，与 API 的 LayerResult 对应）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Decision = Literal["pass", "warn", "modify", "block", "skipped"]


@dataclass
class DetectorHit:
    """单条命中。"""

    category: str  # 如 "S2" / "profanity" / "INJECTION" / "secret:aws_key"
    snippet: str = ""  # 命中片段
    score: float = 0.0  # 该条命中置信度/权重
    extra: dict = field(default_factory=dict)


@dataclass
class DetectorResult:
    """单层检测结果。"""

    name: str
    hit: bool = False
    decision: Decision = "pass"
    hits: list[DetectorHit] = field(default_factory=list)
    latency_ms: int = 0
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "hit": self.hit,
            "decision": self.decision,
            "hits": [h.__dict__ for h in self.hits],
            "latency_ms": self.latency_ms,
            "details": self.raw,
        }
