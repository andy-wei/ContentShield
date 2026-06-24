"""编排器：调度四层 detector、融合结果、写审计。

融合策略：
- 任一层 block → 整体 block
- 否则任一层 warn → warn
- 否则 pass
风险评分：综合各层 hit 与置信度，加权得到 0-1。
"""
from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import select

from ..config import settings
from ..db import async_session, init_db
from ..models import AuditLog, CategoryRule, DlpRule, LexiconEntry
from .detectors.base import BaseDetector
from .detectors.cross_verify import CrossVerifyDetector
from .detectors.dlp import BUILTIN_RULES, DlpDetector
from .detectors.indirect_injection import IndirectInjectionDetector
from .detectors.lexicon import LexiconDetector
from .detectors.llama_guard import LlamaGuardDetector
from .detectors.prompt_guard import PromptGuardDetector
from .result import DetectorResult

logger = logging.getLogger(__name__)


# 层级权重（贡献到风险评分）
LAYER_WEIGHTS = {
    "lexicon": 0.2,
    "prompt_guard": 0.35,
    "llama_guard": 0.35,
    "dlp": 0.3,
    "indirect_injection": 0.4,  # 间接注入权重最高（最危险）
    "cross_verify": 0.25,  # L4 交叉验证（补充意见，权重适中）
}


def _to_layer_result(r: DetectorResult):
    from ..schemas.moderation import LayerResult

    return LayerResult(
        name=r.name,
        hit=r.hit,
        decision=r.decision,  # type: ignore[arg-type]
        details=r.raw,
        latency_ms=r.latency_ms,
    )


class Orchestrator:
    def __init__(self) -> None:
        self.lexicon = LexiconDetector()
        self.prompt_guard = PromptGuardDetector()
        self.llama_guard = LlamaGuardDetector()
        self.dlp = DlpDetector()
        self.indirect_injection = IndirectInjectionDetector()
        self.cross_verify = CrossVerifyDetector()

    @property
    def detectors(self) -> list[BaseDetector]:
        return [
            self.lexicon,
            self.prompt_guard,
            self.llama_guard,
            self.dlp,
            self.indirect_injection,
            self.cross_verify,
        ]

    async def warmup(self) -> None:
        """建表 + seed 默认规则 + 预热各层。"""
        await init_db()
        await self._seed_defaults()
        await asyncio.gather(
            *[d.warmup() for d in self.detectors],
            return_exceptions=True,
        )
        logger.info("Orchestrator warmed up (%s profile)", settings.inference_profile)

    async def shutdown(self) -> None:
        for d in self.detectors:
            try:
                await d.shutdown()
            except Exception:  # noqa: BLE001
                pass

    async def invalidate_caches(self) -> None:
        """规则变更后重载词库/DLP/类别缓存。"""
        await self.lexicon.invalidate()
        await self.dlp.invalidate()
        await self.llama_guard.invalidate()

    async def _seed_defaults(self) -> None:
        """首次启动 seed 默认类别 / 词库 / DLP 规则（异步，复用主 engine）。"""
        async with async_session() as session:
            # 类别
            existing_cats = set(
                (await session.execute(select(CategoryRule.code))).scalars().all()
            )
            from .categories import CORE_ENABLED, DEFAULT_CATEGORIES

            for cat in DEFAULT_CATEGORIES:
                if cat["code"] not in existing_cats:
                    is_core = cat["code"] in CORE_ENABLED
                    session.add(
                        CategoryRule(**cat, enabled=is_core, action="block")
                    )

            # DLP 规则
            existing_dlp = set(
                (await session.execute(select(DlpRule.name))).scalars().all()
            )
            for rule in BUILTIN_RULES:
                if rule["name"] not in existing_dlp:
                    session.add(DlpRule(**rule, enabled=True))

            # 词库（从 data/lexicons/*.json 加载）
            await self._seed_lexicon(session)

            await session.commit()

    async def _seed_lexicon(self, session) -> None:
        import json
        import os

        lex_dir = os.path.join(settings.data_dir, "lexicons")
        if not os.path.isdir(lex_dir):
            return

        existing = set(
            (await session.execute(
                select(LexiconEntry.term, LexiconEntry.lang)
            )).all()
        )

        added = 0
        for fname in os.listdir(lex_dir):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(lex_dir, fname), encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to load lexicon %s: %s", fname, e)
                continue
            lang = data.get("lang", "zh")
            category = data.get("category", "profanity")
            action = data.get("action", "block")
            for term in data.get("terms", []):
                if not term or (term, lang) in existing:
                    continue
                session.add(
                    LexiconEntry(
                        term=term,
                        lang=lang,
                        category=category,
                        action=action,
                        enabled=True,
                    )
                )
                existing.add((term, lang))
                added += 1
        if added:
            logger.info("Seeded %d lexicon entries", added)

    async def health(self) -> dict:
        """各后端健康状态。"""
        from ..inference.base import get_llama_guard_backend

        lg = get_llama_guard_backend()
        results = await asyncio.gather(
            lg.health(),
            self._check_prompt_guard_health(),
            return_exceptions=True,
        )
        return {
            "llama_guard": _safe(results[0]),
            "prompt_guard": _safe(results[1]),
        }

    async def _check_prompt_guard_health(self) -> dict:
        """探测 Prompt Guard 服务（独立 HTTP，非 llama.cpp）。"""
        if settings.prompt_guard_backend == "off":
            return {"status": "disabled"}
        import httpx

        base = settings.prompt_guard_base_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                r = await c.get(f"{base}/health")
                return {
                    "status": "ok" if r.status_code == 200 else "error",
                    "http": r.status_code,
                    "endpoint": base,
                }
        except Exception as e:  # noqa: BLE001
            return {"status": "unreachable", "error": str(e), "endpoint": base}

    async def moderate(
        self,
        text: str,
        *,
        source: str = "user_prompt",
        skip_audit: bool = False,
        identity: dict | None = None,
    ) -> dict:
        """执行五层检测，返回融合结果。

        identity: 调用者身份 dict（principal_id/subject/scopes），用于审计归因。
        """
        t0 = time.perf_counter()

        # 六层并行（L0/L3 本地正则，L1/L2/L1.5/L4 走网络）
        results = await asyncio.gather(
            self.lexicon.detect(text, source=source),
            self.prompt_guard.detect(text, source=source),
            self.llama_guard.detect(text, source=source),
            self.dlp.detect(text, source=source),
            self.indirect_injection.detect(text, source=source),
            self.cross_verify.detect(text, source=source),
        )

        merged = self._merge(results, text=text)
        total_ms = int((time.perf_counter() - t0) * 1000)
        merged["latency_ms"] = total_ms

        if not skip_audit:
            try:
                await self._write_audit(text, source, merged, results, identity)
            except Exception as e:  # noqa: BLE001
                logger.warning("Audit write failed: %s", e)

        return merged

    def _merge(self, results: list[DetectorResult], text: str = "") -> dict:
        """融合四层结果。若决策为 modify，生成脱敏文本。"""
        from ..schemas.moderation import LayerResult

        layer_map = {r.name: r for r in results}

        # 决策（优先级：block > modify > warn > pass）
        decision = "pass"
        block_layers = set()  # 记录哪些层触发了 block
        for r in results:
            if r.decision == "block":
                decision = "block"
                block_layers.add(r.name)
                # 注意：不 break，继续记录所有 block 层
            elif r.decision == "modify" and decision in ("pass", "warn"):
                decision = "modify"
            elif r.decision == "warn" and decision == "pass":
                decision = "warn"

        # PII 脱敏优先：若 block 仅来自 LlamaGuard（S-unknown 泄露）且 DLP 层
        # 有 modify 命中，则降级为 modify（用 DLP 精确脱敏替代粗暴拦截）。
        # 注入/越狱/间接注入的 block 不降级（这些是真正的攻击）。
        dlp_result = layer_map.get("dlp")
        injection_blocked = block_layers & {"prompt_guard", "indirect_injection"}
        dlp_modify_hit = (
            dlp_result
            and dlp_result.hit
            and any(h.extra.get("action") in ("modify", "warn") for h in dlp_result.hits)
        )
        if (
            decision == "block"
            and block_layers <= {"llama_guard"}  # block 仅来自 L2
            and not injection_blocked  # 非注入攻击
            and dlp_modify_hit  # DLP 有可脱敏的命中
        ):
            decision = "modify"

        # 风险评分：各层加权 * 命中强度
        risk = 0.0
        for r in results:
            if not r.hit:
                continue
            weight = LAYER_WEIGHTS.get(r.name, 0.25)
            layer_score = max((h.score for h in r.hits), default=0.5)
            risk += weight * layer_score
        risk = min(risk, 1.0)

        # 类别与说明
        categories: list[str] = []
        explanations: list[str] = []
        for r in results:
            if not r.hit:
                continue
            for h in r.hits:
                categories.append(h.category)
                explanations.append(self._explain(r.name, h))

        layers = {r.name: _to_layer_result(r) for r in results}

        # 脱敏文本生成：modify 决策直接脱敏；warn 决策仅当 DLP 层命中时脱敏
        # （危害内容 warn 不脱敏，只有 PII/URL 等敏感信息 warn 才脱敏）
        modified_text = None
        dlp_result = layer_map.get("dlp")
        if text and (decision == "modify" or (decision == "warn" and dlp_result and dlp_result.hit)):
            redacted, redact_hits = self.dlp.redact(text)
            if redact_hits and redacted != text:
                modified_text = redacted
                explanations.append(
                    f"L3 DLP: 已脱敏 {len(redact_hits)} 处敏感信息，转发脱敏后文本"
                )

        return {
            "decision": decision,
            "risk_score": round(risk, 4),
            "layers": layers,
            "categories": categories,
            "explanations": explanations,
            "modified_text": modified_text,
            "latency_ms": 0,  # 由调用方覆盖
        }

    def _explain(self, layer: str, hit) -> str:
        cat = hit.category
        if layer == "lexicon":
            return f"L0 词库: 命中「{cat}」类敏感词"
        if layer == "prompt_guard":
            label = hit.extra.get("label", cat)
            return f"L1 PromptGuard: 提示词{label}（置信度 {hit.score:.2f}）"
        if layer == "llama_guard":
            name = hit.extra.get("name", cat)
            return f"L2 LlamaGuard: 命中 {cat} ({name})"
        if layer == "dlp":
            return f"L3 DLP: 命中敏感信息「{cat}」（{hit.snippet}）"
        if layer == "indirect_injection":
            matched = hit.extra.get("matched", "")
            return f"L1.5 间接注入: 命中{cat}（{matched}）"
        if layer == "cross_verify":
            cat_name = hit.extra.get("category_name", cat)
            reason = hit.extra.get("reason", "")
            return f"L4 交叉验证: {cat_name}（{reason}）"
        return f"{layer}: {cat}"

    async def _write_audit(
        self,
        text: str,
        source: str,
        merged: dict,
        results: list[DetectorResult],
        identity: dict | None = None,
    ) -> None:
        stored_text = text
        if settings.audit_redact_pii:
            stored_text = self._redact_text(text)

        # 身份归因（NHI 动态凭据管理）
        principal_id = identity.get("principal_id") if identity else None
        subject = identity.get("subject", "") if identity else ""
        scopes = identity.get("scopes", "") if identity else ""

        layers_dict = {r.name: r.to_dict() for r in results}
        async with async_session() as session:
            log = AuditLog(
                source=source,
                input_text=stored_text,
                input_length=len(text),
                decision=merged["decision"],
                risk_score=merged["risk_score"],
                categories=merged["categories"],
                layers=layers_dict,
                explanations=merged["explanations"],
                latency_ms=merged["latency_ms"],
                principal_id=principal_id,
                subject=subject,
                scopes=scopes,
            )
            session.add(log)
            await session.commit()

    def _redact_text(self, text: str) -> str:
        """对原文中的 PII/密钥片段打码。"""
        import re

        redacted = text
        for pattern, _name, _cat, _act, _w in self.dlp._rules:  # noqa: SLF001
            redacted = pattern.sub(lambda m: m.group(0)[:2] + "***", redacted)
        return redacted


async def _null_health() -> dict:
    return {"status": "disabled"}


def _safe(val) -> dict:
    if isinstance(val, Exception):
        return {"status": "error", "error": str(val)}
    if isinstance(val, dict):
        return val
    return {"status": "unknown"}


# 单例
orchestrator = Orchestrator()
