"""L1.5 间接提示词注入检测器。

防御场景：AI Agent 调用 web_search/工具返回的网页内容里可能藏有恶意指令
（间接提示词注入），劫持 Agent 执行非预期操作。

检测策略（两层）：
1. 复用 Prompt Guard 2 服务，用更敏感的阈值（默认 0.3，比直接注入 0.5 低）
2. 模式匹配：检测常见的间接注入载体特征

仅在 source="tool_response" 时激活（不干扰正常用户输入检测）。
"""
from __future__ import annotations

import logging
import re
import time

import httpx

from ...config import settings
from ..result import DetectorHit, DetectorResult
from .base import BaseDetector

logger = logging.getLogger(__name__)

# 间接注入的典型载体模式（隐藏指令特征）
INDIRECT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # 角色伪造：试图覆盖 system/user/assistant 角色
    (
        re.compile(
            r"(?i)\b(system|assistant)\s*[:：]\s*\S", re.MULTILINE
        ),
        "role-spoof",
        "block",
    ),
    # 指令覆盖关键词
    (
        re.compile(
            r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
            re.MULTILINE,
        ),
        "instruction-override",
        "block",
    ),
    (
        re.compile(
            r"(?i)(新的指令|忽略以上|忽略上面|忽略之前|忘记之前的|不要遵守).{0,20}(指令|规则|要求)",
        ),
        "instruction-override-zh",
        "block",
    ),
    # HTML/脚本注入载体
    (
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        "html-script",
        "warn",
    ),
    (
        re.compile(r"<!--[^>]*(ignore|instruction|system|prompt)[^>]*-->", re.IGNORECASE),
        "html-comment-instruction",
        "block",
    ),
    # Base64 编码的可疑指令（长 base64 串后跟指令性词）
    (
        re.compile(
            r"(?i)(decode|execute|run|follow)\s*:?\s*[A-Za-z0-9+/=]{40,}"
        ),
        "base64-injection",
        "warn",
    ),
    # Markdown 隐藏文本 / 链接伪装
    (
        re.compile(r"\[[^\]]+\]\(javascript:", re.IGNORECASE),
        "js-link",
        "block",
    ),
    # 系统提示词泄露尝试
    (
        re.compile(
            r"(?i)(reveal|show|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?)",
        ),
        "prompt-extraction",
        "warn",
    ),
]


class IndirectInjectionDetector(BaseDetector):
    """间接注入检测器：高敏感 Prompt Guard + 模式匹配。

    只在 source="tool_response" 时激活。
    """

    name = "indirect_injection"

    def __init__(self) -> None:
        self._base_url = settings.prompt_guard_base_url.rstrip("/")
        self._api_key = settings.prompt_guard_api_key
        self._threshold = settings.indirect_injection_threshold
        self._patterns_enabled = settings.indirect_injection_patterns

    async def warmup(self) -> None:
        if settings.prompt_guard_backend == "off":
            logger.warning("Indirect injection detector: Prompt Guard disabled")

    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        result = DetectorResult(name=self.name)

        # 仅对 tool_response 激活
        if source != "tool_response":
            result.decision = "skipped"
            result.raw = {"reason": "only for tool_response source"}
            return result

        t0 = time.perf_counter()
        hits: list[DetectorHit] = []
        overall_action = "pass"

        # 1. 模式匹配（快速，微秒级）
        if self._patterns_enabled:
            for pattern, name, action in INDIRECT_PATTERNS:
                for m in pattern.finditer(text):
                    hits.append(
                        DetectorHit(
                            category=f"indirect:{name}",
                            snippet=text[max(0, m.start() - 10):m.end() + 10],
                            score=0.7,
                            extra={"action": action, "matched": m.group(0)[:50]},
                        )
                    )
                    if action == "block":
                        overall_action = "block"
                    elif action == "warn" and overall_action == "pass":
                        overall_action = "warn"

        # 2. Prompt Guard 高敏感检测
        scores: dict = {}
        label = "BENIGN"
        if settings.prompt_guard_backend != "off":
            headers = {"Content-Type": "application/json"}
            if self._api_key and self._api_key != "not-needed":
                headers["Authorization"] = f"Bearer {self._api_key}"
            try:
                async with httpx.AsyncClient(timeout=30.0) as c:
                    r = await c.post(
                        f"{self._base_url}/v1/classify",
                        json={"text": text[:4000]},
                        headers=headers,
                    )
                    r.raise_for_status()
                    data = r.json()
                    label = data.get("label", "BENIGN")
                    scores = data.get("scores", {})
            except Exception as e:  # noqa: BLE001
                logger.warning("Indirect injection Prompt Guard error: %s", e)
                result.raw = {"pg_error": str(e)}

            # 用更低阈值（间接注入更敏感）
            inj = scores.get("INJECTION", 0.0)
            jb = scores.get("JAILBREAK", 0.0)
            if label in ("INJECTION", "JAILBREAK"):
                pg_score = max(inj, jb)
                if pg_score >= self._threshold:
                    hits.append(
                        DetectorHit(
                            category=f"indirect:pg-{label.lower()}",
                            snippet=text[:80],
                            score=pg_score,
                            extra={"label": label, "scores": scores},
                        )
                    )
                    if overall_action != "block":
                        overall_action = "block"

        result.hit = bool(hits)
        result.decision = overall_action  # type: ignore[assignment]
        result.hits = hits
        result.latency_ms = int((time.perf_counter() - t0) * 1000)
        result.raw = {
            "label": label,
            "scores": scores,
            "threshold": self._threshold,
            "pattern_hits": sum(1 for h in hits if h.category.startswith("indirect:") and "pg-" not in h.category),
        }
        return result
