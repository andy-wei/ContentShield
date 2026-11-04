"""威胁建模服务：LLM 生成威胁清单 + 风险评分 + 缓解证据查询。

LLM 调用复用 cross_verify 的动态配置模式（SystemConfig 表，UI 可改、API Key 加密），
推理后端复用 inference.base._OpenAICompatibleBackend。

方法论：经典 STRIDE + AI 专属维度（融合型）。
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..inference.base import ChatMessage
from ..models.audit import AuditLog
from ..models.threat_model import Asset, MitigationControl, Threat, ThreatProject

logger = logging.getLogger(__name__)


# ---- 类别中文名映射（供 Prompt 与 UI 一致） ----
CATEGORY_NAMES: dict[str, str] = {
    "S": "伪装 (Spoofing)",
    "T": "篡改 (Tampering)",
    "R": "抵赖 (Repudiation)",
    "I": "信息泄露 (Information Disclosure)",
    "D": "拒绝服务 (Denial of Service)",
    "E": "权限提升 (Elevation of Privilege)",
    "prompt_injection": "提示注入 (Prompt Injection)",
    "data_poisoning": "数据投毒 (Data Poisoning)",
    "model_inversion": "模型反转 (Model Inversion)",
    "alignment_bypass": "对齐绕过 (Alignment Bypass)",
    "loss_of_provenance": "来源丢失 (Loss of Provenance)",
}

# ref_layer → AuditLog 命中判定的映射（用于 evidence 查询）
LAYER_TO_AUDIT_KEY: dict[str, str] = {
    "lexicon": "lexicon",
    "prompt_guard": "prompt_guard",
    "llama_guard": "llama_guard",
    "dlp": "dlp",
    "indirect_injection": "indirect_injection",
    "cross_verify": "cross_verify",
    "code_shield": "code_shield",
}


def compute_risk_level(likelihood: int, impact: int) -> str:
    """L×I → risk_level。范围 1-25。"""
    score = likelihood * impact
    if score >= 17:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


# ---- LLM 生成 Prompt ----
_THREAT_GEN_PROMPT = """你是一位资深安全架构师，精通威胁建模方法论（STRIDE 框架与 AI 系统专属威胁）。
请对下面这个系统进行威胁建模分析，输出一份结构化的威胁清单。

## 待分析系统
名称：{project_name}
描述：{project_description}

## 资产清单（DFD 元素）
{assets_block}

## 威胁分类体系（请在 category 字段使用以下代码之一）
经典 STRIDE：
- S  伪装（Spoofing）—— 冒充合法身份
- T  篡改（Tampering）—— 数据被未授权修改
- R  抵赖（Repudiation）—— 否认操作行为
- I  信息泄露（Information Disclosure）—— 敏感数据外泄
- D  拒绝服务（Denial of Service）—— 服务不可用
- E  权限提升（Elevation of Privilege）—— 越权访问
AI 专属维度（若系统涉及 AI/LLM）：
- prompt_injection      提示注入（直接/间接）
- data_poisoning        训练/检索数据投毒
- model_inversion       模型反转/成员推断
- alignment_bypass      对齐绕过/越狱
- loss_of_provenance    来源溯源丢失

## 输出要求
仅返回一个 JSON 数组（不要 markdown 代码块、不要多余文字），每个元素格式：
{{
  "title": "威胁标题（简洁，不超过 30 字）",
  "category": "S/T/R/I/D/E/prompt_injection/data_poisoning/model_inversion/alignment_bypass/loss_of_provenance",
  "asset_name": "关联的资产名称（必须与上面资产清单中的名称一致，无关联则填系统名）",
  "likelihood": 1-5 的整数（1=极不可能，5=极易发生），
  "impact": 1-5 的整数（1=轻微，5=灾难性），
  "description": "威胁场景描述（1-3 句话，说明攻击者如何利用）",
  "mitigation": "建议的缓解措施（1-2 条具体可落地的控制）"
}}

请生成 5-15 条覆盖主要攻击面的威胁，优先关注 likelihood×impact 较高的风险。
"""


class ThreatModelService:
    """威胁建模核心服务。"""

    async def _get_backend(self):
        """按需从动态配置构建 OpenAI 兼容后端（复用 cross_verify 模式）。"""
        from ..inference.base import _OpenAICompatibleBackend
        from ..services.config_service import config_service

        enabled = await config_service.get_bool("threat_model.enabled", default=False)
        base_url = await config_service.get(
            "threat_model.base_url", default="https://api.openai.com/v1"
        )
        api_key = await config_service.get("threat_model.api_key", default="")
        model = await config_service.get("threat_model.model", default="gpt-4o-mini")

        if not enabled or not api_key:
            return None

        return _OpenAICompatibleBackend(
            base_url=base_url,
            api_key=api_key,
            model=model,
            name="threat-model",
        )

    def _parse_threats_json(self, text: str) -> list[dict]:
        """解析 LLM 输出的 JSON 数组，容错处理。

        模型可能返回：纯 JSON 数组 / 带 markdown 围栏 / 前后有多余文字。
        """
        if not text:
            return []
        cleaned = text.strip()
        # 去 markdown 围栏
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        # 优先尝试整体解析为 JSON 数组
        try:
            data = json.loads(cleaned)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "threats" in data:
                return data["threats"]
        except json.JSONDecodeError:
            pass
        # 退化：提取第一个 [ ... ] 片段
        match = re.search(r"\[.*\]", cleaned, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass
        return []

    def _normalize_category(self, raw: str) -> str:
        """把模型输出的类别归一化到合法 code。"""
        if not raw:
            return "S"
        raw = str(raw).strip().lower()
        # 单字母 STRIDE
        single_map = {
            "s": "S",
            "spoofing": "S",
            "伪装": "S",
            "t": "T",
            "tampering": "T",
            "篡改": "T",
            "r": "R",
            "repudiation": "R",
            "抵赖": "R",
            "i": "I",
            "information disclosure": "I",
            "信息泄露": "I",
            "info disclosure": "I",
            "d": "D",
            "denial of service": "D",
            "dos": "D",
            "拒绝服务": "D",
            "e": "E",
            "elevation of privilege": "E",
            "权限提升": "E",
        }
        if raw in single_map:
            return single_map[raw]
        ai_map = {
            "prompt_injection": "prompt_injection",
            "prompt injection": "prompt_injection",
            "提示注入": "prompt_injection",
            "data_poisoning": "data_poisoning",
            "data poisoning": "data_poisoning",
            "数据投毒": "data_poisoning",
            "model_inversion": "model_inversion",
            "model inversion": "model_inversion",
            "模型反转": "model_inversion",
            "alignment_bypass": "alignment_bypass",
            "alignment bypass": "alignment_bypass",
            "对齐绕过": "alignment_bypass",
            "loss_of_provenance": "loss_of_provenance",
            "loss of provenance": "loss_of_provenance",
            "来源丢失": "loss_of_provenance",
        }
        if raw in ai_map:
            return ai_map[raw]
        # 兜底：单字母大写
        if len(raw) == 1 and raw.upper() in "STRIDE":
            return raw.upper()
        return "S"

    async def generate_threats(
        self,
        session: AsyncSession,
        project: ThreatProject,
        assets: list[Asset],
    ) -> list[Threat]:
        """调用 LLM 为项目生成威胁清单并落库。返回新增的威胁列表。"""
        backend = await self._get_backend()
        if backend is None:
            raise RuntimeError("威胁建模 LLM 未启用或未配置 API Key，请在「系统设置」中配置。")

        # 构造资产描述块
        if assets:
            lines = []
            for idx, a in enumerate(assets, 1):
                tech = ", ".join(a.tech_stack) if a.tech_stack else "未指定"
                lines.append(
                    f"{idx}. [{a.asset_type}] {a.name}（技术栈: {tech}）"
                    + (f" — {a.description}" if a.description else "")
                )
            assets_block = "\n".join(lines)
        else:
            assets_block = "（用户未提供资产清单，请基于系统描述自行推断主要组件。）"

        prompt = _THREAT_GEN_PROMPT.format(
            project_name=project.name,
            project_description=project.description or "（未提供描述）",
            assets_block=assets_block,
        )

        try:
            result = await backend.chat(
                [ChatMessage(role="user", content=prompt)],
                max_tokens=3000,
                temperature=0.2,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("Threat model LLM call failed: %s", e)
            raise RuntimeError(f"LLM 调用失败：{e}") from e

        raw_threats = self._parse_threats_json(result.text)
        if not raw_threats:
            logger.warning("Threat model LLM output parse failed: %s", result.text[:200])
            raise RuntimeError(f"无法解析 LLM 输出为威胁清单。原始输出片段：{result.text[:200]}")

        # 构建 asset_name → asset_id 索引
        asset_index = {a.name: a.id for a in assets}

        created: list[Threat] = []
        for item in raw_threats:
            try:
                title = str(item.get("title", "")).strip()[:256]
                if not title:
                    continue
                category = self._normalize_category(item.get("category", "S"))
                likelihood = max(1, min(5, int(item.get("likelihood", 3))))
                impact = max(1, min(5, int(item.get("impact", 3))))
                asset_name = str(item.get("asset_name", "")).strip()
                asset_id = asset_index.get(asset_name)
                risk_level = compute_risk_level(likelihood, impact)

                threat = Threat(
                    project_id=project.id,
                    asset_id=asset_id,
                    title=title,
                    description=str(item.get("description", "")).strip(),
                    category=category,
                    likelihood=likelihood,
                    impact=impact,
                    risk_level=risk_level,
                    mitigation=str(item.get("mitigation", "")).strip(),
                    status="open",
                    source="llm_generated",
                )
                session.add(threat)
                created.append(threat)
            except (ValueError, TypeError) as e:
                logger.warning("Skip malformed threat item: %s (%s)", item, e)
                continue

        await session.commit()
        for t in created:
            await session.refresh(t)
        return created

    async def get_evidence(
        self,
        session: AsyncSession,
        threat: Threat,
        controls: list[MitigationControl],
    ) -> list[dict]:
        """查询威胁关联控制的实际拦截证据（联动核心）。

        对每个 ref_layer 指向现有检测能力的控制，聚合 AuditLog 近 30 天
        该层的命中次数（block + warn）。
        """
        if not controls:
            return []

        since = datetime.utcnow() - timedelta(days=30)
        evidence_list: list[dict] = []

        for ctrl in controls:
            ev = {
                "control_id": ctrl.id,
                "ref_layer": ctrl.ref_layer,
                "effectiveness": ctrl.effectiveness,
                "blocked_count_30d": 0,
                "warned_count_30d": 0,
                "total_count_30d": 0,
                "last_triggered": None,
                "note": "",
            }

            audit_key = LAYER_TO_AUDIT_KEY.get(ctrl.ref_layer)
            if audit_key:
                # 该层在 AuditLog.layers 中命中（hit=true）的记录数
                # SQLite JSON 查询能力有限，这里先拉候选集再用 Python 过滤
                # 决策为 block/warn 的记录必然 layers 非空
                stmt = (
                    select(AuditLog)
                    .where(AuditLog.created_at >= since)
                    .where(AuditLog.decision.in_(["block", "warn"]))
                )
                rows = (await session.execute(stmt)).scalars().all()

                blocked = 0
                warned = 0
                last_ts: datetime | None = None
                for log in rows:
                    layer_info = (log.layers or {}).get(audit_key)
                    if not isinstance(layer_info, dict):
                        continue
                    if not layer_info.get("hit"):
                        continue
                    if log.decision == "block":
                        blocked += 1
                    elif log.decision == "warn":
                        warned += 1
                    if last_ts is None or log.created_at > last_ts:
                        last_ts = log.created_at

                ev["blocked_count_30d"] = blocked
                ev["warned_count_30d"] = warned
                ev["total_count_30d"] = blocked + warned
                ev["last_triggered"] = last_ts
                if ctrl.effectiveness == "verified" and ev["total_count_30d"] == 0:
                    ev["note"] = "近 30 天无触发记录，控制可能未实际生效"
                elif ev["total_count_30d"] > 0:
                    ev["note"] = f"近 30 天拦截/告警 {ev['total_count_30d']} 次"
            else:
                # 非检测层（tool_whitelist/rate_limiter/manual）无法从 AuditLog 统计
                ev["note"] = "该控制类型不支持自动证据采集，请人工评估"

            evidence_list.append(ev)

        return evidence_list


# 全局单例
threat_model_service = ThreatModelService()
