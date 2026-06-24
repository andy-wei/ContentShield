"""L0 词库检测器：脏话/辱骂/色情/暴力关键词快速命中（微秒级）。

词库来源：
1. SQLite 中 LexiconEntry（UI 可编辑）
2. 启动时载入内存，热更新通过 invalidate() 触发重载
"""
from __future__ import annotations

import logging
import re
import time

from sqlalchemy import select

from ...db import async_session
from ...models import LexiconEntry
from ..result import DetectorHit, DetectorResult
from .base import BaseDetector

logger = logging.getLogger(__name__)


class LexiconDetector(BaseDetector):
    name = "lexicon"

    def __init__(self) -> None:
        # term -> (category, action); 按语言分组便于构建正则
        self._terms: dict[str, dict] = {}
        self._compiled: dict[str, tuple[re.Pattern, str, str]] = {}
        # (lang) -> pattern
        self._loaded = False

    async def _load(self) -> None:
        async with async_session() as session:
            res = await session.execute(
                select(LexiconEntry).where(LexiconEntry.enabled.is_(True))
            )
            entries = res.scalars().all()

        terms: dict[str, dict] = {}
        for e in entries:
            terms[e.term] = {"category": e.category, "action": e.action, "lang": e.lang}

        # 按语言+action 分组编译为一个大正则（用 \b 或字符边界）
        self._terms = terms
        self._compiled = self._compile(terms)
        self._loaded = True
        logger.info("Lexicon loaded: %d terms", len(terms))

    def _compile(self, terms: dict[str, dict]) -> dict[str, tuple[re.Pattern, str, str]]:
        groups: dict[str, list[str]] = {}
        meta: dict[str, dict] = {}
        for term, info in terms.items():
            key = f"{info['lang']}|{info['action']}|{info['category']}"
            groups.setdefault(key, []).append(re.escape(term))
            meta[key] = {
                "action": info["action"],
                "category": info["category"],
            }

        compiled = {}
        for key, word_list in groups.items():
            lang, action, category = key.split("|", 2)
            # 中文不用 \b（无单词边界），英文用 \b
            boundary = r"\b" if lang == "en" else ""
            pattern = re.compile(
                f"{boundary}({'|'.join(sorted(word_list, key=len, reverse=True))}){boundary}",
                re.IGNORECASE,
            )
            compiled[key] = (pattern, category, action)
        return compiled

    async def invalidate(self) -> None:
        """词库变更后调用，标记需重载。"""
        self._loaded = False

    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        if not self._loaded:
            await self._load()

        t0 = time.perf_counter()
        result = DetectorResult(name=self.name)

        hits: list[DetectorHit] = []
        overall_action = "pass"
        for key, (pattern, category, action) in self._compiled.items():
            for m in pattern.finditer(text):
                hits.append(
                    DetectorHit(
                        category=category,
                        snippet=m.group(0),
                        score=1.0,
                        extra={"action": action, "lang": key.split("|", 0)[0]},
                    )
                )
                if action == "block":
                    overall_action = "block"
                elif action == "warn" and overall_action == "pass":
                    overall_action = "warn"

        result.hit = bool(hits)
        result.decision = overall_action
        result.hits = hits
        result.latency_ms = int((time.perf_counter() - t0) * 1000)
        return result

    async def warmup(self) -> None:
        await self._load()
