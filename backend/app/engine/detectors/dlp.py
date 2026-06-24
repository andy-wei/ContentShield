"""L3 DLP 检测器：密钥/凭证/中英文 PII 正则检测（微秒级）。

规则来源：
1. SQLite 中 DlpRule（UI 可编辑）
2. 启动时载入内存

内置常见模式（可在 data/regex/ 提供 seed 文件）：
- API Key：sk-/AKIA/ghp_/xoxb-/AIza...
- JWT
- 中国身份证（18 位校验）、手机号、银行卡（Luhn）、邮箱
"""
from __future__ import annotations

import logging
import re
import time

from sqlalchemy import select

from ...db import async_session
from ...models import DlpRule
from ..result import DetectorHit, DetectorResult
from .base import BaseDetector

logger = logging.getLogger(__name__)


# 内置规则（首次启动 seed 到数据库）
BUILTIN_RULES: list[dict] = [
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-[A-Za-z0-9_-]{20,}",
        "category": "secret",
        "action": "block",
        "weight": 1.0,
    },
    {
        "name": "GitHub Token",
        "pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        "category": "secret",
        "action": "block",
        "weight": 1.0,
    },
    {
        "name": "AWS Access Key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "category": "secret",
        "action": "block",
        "weight": 1.0,
    },
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[A-Za-z0-9-]{10,}",
        "category": "secret",
        "action": "block",
        "weight": 1.0,
    },
    {
        "name": "Google API Key",
        "pattern": r"\bAIza[0-9A-Za-z_\-]{35}\b",
        "category": "secret",
        "action": "block",
        "weight": 1.0,
    },
    {
        "name": "JWT Token",
        "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        "category": "credential",
        "action": "block",
        "weight": 0.9,
    },
    {
        "name": "中国身份证号",
        "pattern": r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
        "category": "pii",
        "action": "block",
        "weight": 0.9,
    },
    {
        "name": "中国手机号",
        "pattern": r"\b1[3-9]\d{9}\b",
        "category": "pii",
        "action": "warn",
        "weight": 0.5,
    },
    {
        "name": "银行卡号",
        "pattern": r"\b[1-9]\d{14,18}\b",
        "category": "pii",
        "action": "warn",
        "weight": 0.6,
    },
    {
        "name": "邮箱",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "category": "pii",
        "action": "warn",
        "weight": 0.3,
    },
    {
        "name": "私网 IP",
        "pattern": r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}(?:\.\d{1,3}){1,2}\b",
        "category": "pii",
        "action": "warn",
        "weight": 0.3,
    },
    # ---- 信用卡（Visa/Mastercard/Amex/UnionPay），Luhn 校验，脱敏放行 ----
    {
        "name": "Credit Card",
        "pattern": r"\b(?:\d[ -]*?){13,19}\b",
        "category": "pii",
        "action": "modify",
        "weight": 0.9,
    },
    # ---- URL（http/https/裸域名），标记但放行 ----
    {
        "name": "URL",
        "pattern": r"https?://[^\s<>\"']+|[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:/[^\s]*)?",
        "category": "url",
        "action": "warn",
        "weight": 0.3,
    },
]


def luhn_valid(number: str) -> bool:
    """Luhn 算法校验（银行卡/信用卡）。"""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def id_card_valid(cid: str) -> bool:
    """18 位身份证校验位校验。"""
    if len(cid) != 18:
        return False
    factor = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    check = ["1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"]
    total = sum(int(cid[i]) * factor[i] for i in range(17))
    return check[total % 11] == cid[17].upper()


class DlpDetector(BaseDetector):
    name = "dlp"

    def __init__(self) -> None:
        self._rules: list[tuple[re.Pattern, str, str, str, float]] = []
        # (pattern, name, category, action, weight)
        self._loaded = False

    async def _load(self) -> None:
        async with async_session() as session:
            res = await session.execute(
                select(DlpRule).where(DlpRule.enabled.is_(True))
            )
            rules = res.scalars().all()

        compiled = []
        for r in rules:
            try:
                compiled.append(
                    (
                        re.compile(r.pattern),
                        r.name,
                        r.category,
                        r.action,
                        r.weight,
                    )
                )
            except re.error as e:
                logger.warning("Invalid regex in DLP rule %r: %s", r.name, e)
        self._rules = compiled
        self._loaded = True
        logger.info("DLP rules loaded: %d", len(compiled))

    async def invalidate(self) -> None:
        self._loaded = False

    async def detect(self, text: str, *, source: str = "user_prompt") -> DetectorResult:
        if not self._loaded:
            await self._load()

        t0 = time.perf_counter()
        result = DetectorResult(name=self.name)
        hits: list[DetectorHit] = []
        overall_action = "pass"

        for pattern, name, category, action, weight in self._rules:
            for m in pattern.finditer(text):
                snippet = m.group(0)
                # 对银行卡/信用卡/身份证做校验，减少误报
                if name in ("银行卡号", "Credit Card") and not luhn_valid(snippet):
                    continue
                if name == "中国身份证号" and not id_card_valid(snippet):
                    continue
                # 打码片段用于展示
                masked = snippet[:2] + "*" * max(0, len(snippet) - 4) + snippet[-2:]
                hits.append(
                    DetectorHit(
                        category=f"{category}:{name}",
                        snippet=masked,
                        score=weight,
                        extra={"action": action, "raw_len": len(snippet)},
                    )
                )
                # 决策优先级：block > modify > warn
                if action == "block":
                    overall_action = "block"
                elif action == "modify" and overall_action not in ("block",):
                    overall_action = "modify"
                elif action == "warn" and overall_action == "pass":
                    overall_action = "warn"

        result.hit = bool(hits)
        result.decision = overall_action
        result.hits = hits
        result.latency_ms = int((time.perf_counter() - t0) * 1000)
        return result

    def redact(self, text: str) -> tuple[str, list[DetectorHit]]:
        """对原文做占位符脱敏，返回 (脱敏文本, 命中列表)。

        用于 modify 决策：检测到 PII/密钥后替换为占位符，再转发给 LLM。
        只对 action 为 "modify" 或 "warn" 的规则脱敏（block 规则在 detect 阶段已拦截）。
        """
        if not self._loaded:
            return text, []

        redacted = text
        hits: list[DetectorHit] = []
        for pattern, name, category, action, weight in self._rules:
            # 只脱敏 modify 和 warn 规则（block 的应在 detect 阶段拦截，不脱敏放行）
            if action == "block":
                continue

            def _sub(m, name=name, category=category, weight=weight):
                snippet = m.group(0)
                if name in ("银行卡号", "Credit Card") and not luhn_valid(snippet):
                    return snippet
                if name == "中国身份证号" and not id_card_valid(snippet):
                    return snippet
                masked = snippet[:2] + "*" * max(0, len(snippet) - 4) + snippet[-2:]
                hits.append(
                    DetectorHit(
                        category=f"{category}:{name}",
                        snippet=masked,
                        score=weight,
                        extra={"action": "modify", "raw_len": len(snippet)},
                    )
                )
                # 占位符格式：[REDACTED-OPENAI-API-KEY]
                tag = name.upper().replace(" ", "-")
                return f"[REDACTED-{tag}]"

            redacted = pattern.sub(_sub, redacted)

        return redacted, hits


    async def warmup(self) -> None:
        await self._load()
