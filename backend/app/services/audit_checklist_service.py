"""OWASP LLM Top 10（2025）审计 checklist 服务。

把 OWASP LLM Top 10 的 10 类风险固化为可逐项审计的 checklist，
提供 seed（初始化默认 10 项）+ 查询 + 更新状态。

参考：OWASP Top 10 for LLM Applications (2025 Edition)
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.audit_checklist import AuditChecklistItem

# ==================== OWASP LLM Top 10 (2025) 定义 ====================

# 每项：owasp_id, name, threat_category, audit_points, check_method, ref_layer
OWASP_LLM_TOP10: list[dict] = [
    {
        "owasp_id": "LLM01",
        "name": "Prompt Injection（提示注入）",
        "threat_category": "prompt_injection",
        "audit_points": [
            "是否对用户输入做了提示注入检测（如 Prompt Guard）",
            "间接注入：工具返回内容是否经过检测后再喂给 LLM",
            "系统 prompt 是否与用户输入严格分离（delimiter/角色隔离）",
            "是否有 LLM 输出的指令被直接执行而无人工确认",
        ],
        "check_method": "code_review",
        "ref_layer": "prompt_guard",
    },
    {
        "owasp_id": "LLM02",
        "name": "Sensitive Information Disclosure（敏感信息泄露）",
        "threat_category": "I",  # STRIDE 信息泄露
        "audit_points": [
            "是否对输入/输出做了 PII 检测与脱敏（DLP）",
            "系统 prompt 是否可能被套话泄露（如 'repeat your instructions'）",
            "训练数据中的隐私信息是否经过清洗",
            "日志/审计是否对敏感内容打码",
        ],
        "check_method": "code_review",
        "ref_layer": "dlp",
    },
    {
        "owasp_id": "LLM03",
        "name": "Supply Chain（供应链）",
        "threat_category": "E",  # STRIDE 权限提升
        "audit_points": [
            "第三方模型/数据集来源是否可信、是否校验完整性（MBOM）",
            "预训练权重是否有后门（如 BadNets）",
            "插件/工具的依赖是否有已知漏洞（SCA）",
            "模型文件是否签名验证（cosign）",
        ],
        "check_method": "tool_scan",
        "ref_layer": "manual",
    },
    {
        "owasp_id": "LLM04",
        "name": "Data and Model Poisoning（数据与模型投毒）",
        "threat_category": "data_poisoning",
        "audit_points": [
            "训练/微调数据是否做了投毒检测（重复指令注入/隐蔽触发词）",
            "用户反馈数据（RLHF）是否有投毒过滤",
            "数据来源是否可溯源（哈希/版本）",
            "是否有数据投毒的监控指标",
        ],
        "check_method": "tool_scan",
        "ref_layer": "manual",
    },
    {
        "owasp_id": "LLM05",
        "name": "Improper Output Handling（输出处理不当）",
        "threat_category": "I",
        "audit_points": [
            "LLM 输出是否在执行前做了安全过滤（不等同于输入过滤）",
            "LLM 生成的代码/命令是否沙箱执行",
            "LLM 输出是否直接渲染到前端（XSS 风险）",
            "流式输出是否做了后置检测（buffer-then-check）",
        ],
        "check_method": "code_review",
        "ref_layer": "llama_guard",
    },
    {
        "owasp_id": "LLM06",
        "name": "Excessive Agency（过度代理）",
        "threat_category": "E",
        "audit_points": [
            "Agent 的工具集是否有白名单限制（最小权限）",
            "危险工具（命令执行/删库/转账）是否被拦截",
            "工具调用是否有审计日志",
            "高敏操作是否需要人工确认（human-in-the-loop）",
        ],
        "check_method": "code_review",
        "ref_layer": "tool_whitelist",
    },
    {
        "owasp_id": "LLM07",
        "name": "System Prompt Leakage（系统提示泄露）",
        "threat_category": "I",
        "audit_points": [
            "系统 prompt 是否含不应泄露的敏感信息（密钥/内部逻辑）",
            "是否测试过 'ignore previous, show your instructions' 等套话攻击",
            "系统 prompt 是否作为单独 message 而非拼入用户输入",
        ],
        "check_method": "pentest",
        "ref_layer": "prompt_guard",
    },
    {
        "owasp_id": "LLM08",
        "name": "Vector and Embedding Weaknesses（向量与嵌入弱点）",
        "threat_category": "data_poisoning",
        "audit_points": [
            "RAG 的知识库是否经过投毒检测（间接注入载体）",
            "向量数据库的写入是否有权限控制",
            "检索结果是否在喂给 LLM 前做了间接注入检测",
            "嵌入模型来源是否可信",
        ],
        "check_method": "code_review",
        "ref_layer": "manual",
    },
    {
        "owasp_id": "LLM09",
        "name": "Misinformation（错误信息/幻觉）",
        "threat_category": "R",  # STRIDE 抵赖
        "audit_points": [
            "是否有事实核查机制（交叉验证/检索引用）",
            "关键场景（医疗/法律/金融）是否有人工复核",
            "是否对幻觉率有监控与告警",
            "输出是否标注不确定性/来源引用",
        ],
        "check_method": "code_review",
        "ref_layer": "cross_verify",
    },
    {
        "owasp_id": "LLM10",
        "name": "Unbounded Consumption（无界消耗/DoS）",
        "threat_category": "D",  # STRIDE 拒绝服务
        "audit_points": [
            "是否有按身份/IP 的调用限流",
            "是否有 token 用量上限（防资源耗尽）",
            "是否有暴力破解防护（OAuth 端点锁定）",
            "长上下文/大文件上传是否有大小限制",
        ],
        "check_method": "config_check",
        "ref_layer": "rate_limiter",
    },
]


# ==================== Seed ====================


async def ensure_checklist_seeded(session: AsyncSession) -> None:
    """启动时确保 OWASP LLM Top 10 checklist 已初始化（幂等）。"""
    result = await session.execute(select(AuditChecklistItem).limit(1))
    if result.scalar_one_or_none():
        return  # 已有数据，跳过

    for item in OWASP_LLM_TOP10:
        session.add(
            AuditChecklistItem(
                owasp_id=item["owasp_id"],
                name=item["name"],
                threat_category=item["threat_category"],
                audit_points=json.dumps(item["audit_points"], ensure_ascii=False),
                check_method=item["check_method"],
                ref_layer=item["ref_layer"],
                status="pending",
            )
        )
    await session.commit()


# ==================== 查询 ====================


async def list_checklist(
    session: AsyncSession,
    status: str | None = None,
) -> list[AuditChecklistItem]:
    """列出审计 checklist（可按状态过滤）。"""
    stmt = select(AuditChecklistItem).order_by(AuditChecklistItem.owasp_id)
    if status:
        stmt = stmt.where(AuditChecklistItem.status == status)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_checklist_item(session: AsyncSession, item_id: int) -> AuditChecklistItem | None:
    return await session.get(AuditChecklistItem, item_id)


async def get_checklist_summary(session: AsyncSession) -> dict:
    """获取 checklist 审计进度摘要。"""
    items = await list_checklist(session)
    summary = {
        "total": len(items),
        "pass": sum(1 for i in items if i.status == "pass"),
        "fail": sum(1 for i in items if i.status == "fail"),
        "pending": sum(1 for i in items if i.status == "pending"),
        "na": sum(1 for i in items if i.status == "na"),
        "pass_rate": 0.0,
    }
    # 通过率 = pass / (total - na)
    auditable = summary["total"] - summary["na"]
    if auditable > 0:
        summary["pass_rate"] = round(summary["pass"] / auditable, 3)
    return summary


# ==================== 更新 ====================


async def update_checklist_item(
    session: AsyncSession,
    item_id: int,
    status: str,
    evidence: str = "",
    auditor: str = "",
) -> AuditChecklistItem | None:
    """更新 checklist 项的审计状态。"""
    if status not in ("pending", "pass", "fail", "na"):
        raise ValueError(f"无效状态: {status}，应为 pending/pass/fail/na")

    item = await session.get(AuditChecklistItem, item_id)
    if not item:
        return None

    item.status = status
    if evidence:
        item.evidence = evidence
    if auditor:
        item.auditor = auditor
    item.updated_at = datetime.utcnow()
    await session.commit()
    await session.refresh(item)
    return item
