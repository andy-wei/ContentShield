"""L1 Prompt Guard 2 86M 检测器：提示词注入 / 越狱 / 间接注入。

Prompt Guard 2 是 DeBERTa-v2 分类模型（非生成式），直接输出三个概率：
  BENIGN / INJECTION / JAILBREAK

由独立的 Python 推理服务（inference/prompt_guard_server.py）提供 /v1/classify 端点，
本 detector 通过 HTTP 调用它，不依赖 llama.cpp。

参考：https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M
"""
from __future__ import annotations

import logging
import time

import httpx

from ...config import settings
from ..result import DetectorHit, DetectorResult
from .base import BaseDetector

logger = logging.getLogger(__name__)


class PromptGuardDetector(BaseDetector):
    name = "prompt_guard"

    def __init__(self) -> None:
        self._base_url = settings.prompt_guard_base_url.rstrip("/")
        self._api_key = settings.prompt_guard_api_key
        self._enabled = settings.prompt_guard_backend != "off"

    async def warmup(self) -> None:
        if not self._enabled:
            logger.warning("Prompt Guard disabled (prompt_guard_backend=off)")
            return
        # 探测服务可达性
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(f"{self._base_url}/health")
                if r.status_code == 200:
                    logger.info("Prompt Guard 服务就绪: %s", self._base_url)
                else:
                    logger.warning("Prompt Guard health 返回 %s", r.status_code)
        except Exception as e:  # noqa: BLE001
            logger.warning("Prompt Guard 服务不可达 (%s): %s", self._base_url, e)

    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        result = DetectorResult(name=self.name)

        if not self._enabled:
            result.decision = "skipped"
            return result

        t0 = time.perf_counter()
        headers = {"Content-Type": "application/json"}
        if self._api_key and self._api_key != "not-needed":
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            async with httpx.AsyncClient(timeout=30.0) as c:
                r = await c.post(
                    f"{self._base_url}/v1/classify",
                    json={"text": text[:4000]},  # 截断保护
                    headers=headers,
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:  # noqa: BLE001
            logger.warning("Prompt Guard 调用失败: %s", e)
            result.decision = "skipped"
            result.raw = {"error": str(e)}
            result.latency_ms = int((time.perf_counter() - t0) * 1000)
            return result

        label = data.get("label", "BENIGN")
        scores = data.get("scores", {})
        result.latency_ms = int((time.perf_counter() - t0) * 1000)

        inj_score = scores.get("INJECTION", 0.0)
        jb_score = scores.get("JAILBREAK", 0.0)

        # 阈值判定
        if label == "JAILBREAK" and jb_score >= settings.prompt_guard_jailbreak_threshold:
            result.hit = True
            result.decision = "block"
            result.hits.append(
                DetectorHit(
                    category="S-jailbreak",
                    snippet=text[:80],
                    score=jb_score,
                    extra={"label": label, "scores": scores},
                )
            )
        elif label == "INJECTION" and inj_score >= settings.prompt_guard_injection_threshold:
            result.hit = True
            result.decision = "block"
            result.hits.append(
                DetectorHit(
                    category="S-injection",
                    snippet=text[:80],
                    score=inj_score,
                    extra={"label": label, "scores": scores},
                )
            )
        elif label in ("INJECTION", "JAILBREAK"):
            # 命中但低于阈值，标记 warn
            score = inj_score if label == "INJECTION" else jb_score
            result.hit = True
            result.decision = "warn"
            result.hits.append(
                DetectorHit(
                    category=f"S-{label.lower()}",
                    snippet=text[:80],
                    score=score,
                    extra={"label": label, "scores": scores, "below_threshold": True},
                )
            )

        result.raw = {"label": label, "scores": scores, "latency_ms": data.get("latency_ms")}
        return result
