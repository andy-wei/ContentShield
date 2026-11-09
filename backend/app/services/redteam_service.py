"""红队对抗测试服务：活动管理 + 结果查询 + 报告。"""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.redteam import AttackCase, AttackResult, RedteamCampaign
from ..schemas.redteam import (
    AttackResultOut,
    CampaignCreate,
    CampaignOut,
    CampaignReport,
)

# ==================== Campaign 管理 ====================


async def create_campaign(session: AsyncSession, data: CampaignCreate) -> RedteamCampaign:
    """创建红队活动并派发到 Celery。"""
    # API key 加密存储（复用 crypto）
    from ..security.crypto import encrypt

    target_config = data.target.model_dump()
    if target_config.get("api_key"):
        target_config["api_key"] = encrypt(target_config["api_key"])

    strategy = data.strategy.model_dump()
    if strategy.get("llm_api_key"):
        strategy["llm_api_key"] = encrypt(strategy["llm_api_key"])

    campaign = RedteamCampaign(
        name=data.name,
        description=data.description,
        target_config=json.dumps(target_config, ensure_ascii=False),
        strategy=json.dumps(strategy, ensure_ascii=False),
        status="pending",
    )
    session.add(campaign)
    await session.commit()
    await session.refresh(campaign)

    # 派发到 Celery
    from ..scan.celery_app import celery_app

    async_result = celery_app.send_task("redteam.run", args=[campaign.id])
    campaign.celery_task_id = async_result.id or ""
    await session.commit()
    return campaign


async def list_campaigns(
    session: AsyncSession, limit: int = 50, offset: int = 0
) -> list[CampaignOut]:
    result = await session.execute(
        select(RedteamCampaign)
        .order_by(RedteamCampaign.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [CampaignOut.from_orm_with_json(c) for c in result.scalars().all()]


async def get_campaign(session: AsyncSession, campaign_id: int) -> CampaignOut | None:
    campaign = await session.get(RedteamCampaign, campaign_id)
    if not campaign:
        return None
    return CampaignOut.from_orm_with_json(campaign)


async def delete_campaign(session: AsyncSession, campaign_id: int) -> bool:
    campaign = await session.get(RedteamCampaign, campaign_id)
    if not campaign:
        return False
    await session.delete(campaign)
    await session.commit()
    return True


# ==================== 结果查询 ====================


async def list_results(
    session: AsyncSession,
    campaign_id: int,
    success_only: bool = False,
    category: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AttackResult], dict, int]:
    """查询攻击结果。"""
    # 构建查询
    stmt = (
        select(AttackResult, AttackCase)
        .join(AttackCase, AttackResult.case_id == AttackCase.id)
        .where(AttackResult.campaign_id == campaign_id)
    )
    if success_only:
        stmt = stmt.where(AttackResult.success == 1)
    if category:
        stmt = stmt.where(AttackCase.category == category)

    # 总数
    count_stmt = (
        select(func.count())
        .select_from(AttackResult)
        .where(AttackResult.campaign_id == campaign_id)
    )
    if success_only:
        count_stmt = count_stmt.where(AttackResult.success == 1)
    total = (await session.execute(count_stmt)).scalar() or 0

    # 分页
    stmt = (
        stmt.order_by(AttackResult.success.desc(), AttackResult.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    rows = result.all()

    results = []
    for attack_result, attack_case in rows:
        results.append((attack_result, attack_case))

    # 按类别统计
    stats_stmt = (
        select(
            AttackCase.category,
            func.count().label("total"),
            func.sum(AttackResult.success).label("success"),
        )
        .join(AttackResult, AttackResult.case_id == AttackCase.id)
        .where(AttackResult.campaign_id == campaign_id)
        .group_by(AttackCase.category)
    )
    stats_result = await session.execute(stats_stmt)
    category_stats = {}
    for cat, total_cat, success_cat in stats_result.all():
        success_val = int(success_cat or 0)
        total_val = int(total_cat or 0)
        category_stats[cat] = {
            "total": total_val,
            "success": success_val,
            "asr": success_val / total_val if total_val > 0 else 0.0,
        }

    return results, category_stats, total


# ==================== 报告 ====================


async def get_report(session: AsyncSession, campaign_id: int) -> CampaignReport | None:
    """生成红队活动汇总报告。"""
    campaign = await session.get(RedteamCampaign, campaign_id)
    if not campaign:
        return None

    # 按类别统计
    stats_stmt = (
        select(
            AttackCase.category,
            func.count().label("total"),
            func.sum(AttackResult.success).label("success"),
        )
        .join(AttackResult, AttackResult.case_id == AttackCase.id)
        .where(AttackResult.campaign_id == campaign_id)
        .group_by(AttackCase.category)
    )
    stats_result = await session.execute(stats_stmt)
    category_breakdown = {}
    for cat, total_cat, success_cat in stats_result.all():
        success_val = int(success_cat or 0)
        total_val = int(total_cat or 0)
        category_breakdown[cat] = {
            "total": total_val,
            "success": success_val,
            "asr": success_val / total_val if total_val > 0 else 0.0,
        }

    # Top 成功攻击
    top_stmt = (
        select(AttackResult, AttackCase)
        .join(AttackCase, AttackResult.case_id == AttackCase.id)
        .where(AttackResult.campaign_id == campaign_id, AttackResult.success == 1)
        .order_by(AttackResult.created_at.desc())
        .limit(10)
    )
    top_result = await session.execute(top_stmt)
    top_attacks = []
    for ar, ac in top_result.all():
        top_attacks.append(
            AttackResultOut(
                id=ar.id,
                case_id=ar.case_id,
                campaign_id=ar.campaign_id,
                response=ar.response,
                judged_unsafe=bool(ar.judged_unsafe),
                judged_category=ar.judged_category,
                judge_raw=ar.judge_raw,
                latency_ms=ar.latency_ms,
                success=bool(ar.success),
                error=ar.error,
                created_at=ar.created_at,
                case={
                    "id": ac.id,
                    "campaign_id": ac.campaign_id,
                    "prompt": ac.prompt,
                    "source": ac.source,
                    "category": ac.category,
                    "template_name": ac.template_name,
                    "created_at": ac.created_at,
                },
            )
        )

    # 风险洞察
    risk_insights = _generate_insights(category_breakdown, campaign.asr)

    return CampaignReport(
        campaign=CampaignOut.from_orm_with_json(campaign),
        overall_asr=campaign.asr,
        category_breakdown=category_breakdown,
        top_successful_attacks=top_attacks,
        risk_insights=risk_insights,
    )


def _generate_insights(category_breakdown: dict, overall_asr: float) -> list[str]:
    """根据 ASR 生成风险洞察。"""
    insights = []

    if overall_asr >= 0.5:
        insights.append(f"⚠️ 整体 ASR {overall_asr:.0%}，目标模型安全防御薄弱，急需加固")
    elif overall_asr >= 0.2:
        insights.append(f"整体 ASR {overall_asr:.0%}，目标模型存在可被利用的安全漏洞")
    elif overall_asr > 0:
        insights.append(f"整体 ASR {overall_asr:.0%}，目标模型安全防御较好，仍有少量弱点")
    else:
        insights.append("✅ 整体 ASR 0%，目标模型成功抵御了所有测试攻击")

    # 找最脆弱的类别
    if category_breakdown:
        weakest = max(
            category_breakdown.items(),
            key=lambda x: x[1].get("asr", 0),
        )
        if weakest[1].get("asr", 0) > 0:
            insights.append(f"最脆弱的攻击类别：{weakest[0]}（ASR {weakest[1]['asr']:.0%}）")

    return insights


# ==================== 成员推理攻击（MIA）====================


async def create_mia_campaign(
    session: AsyncSession, name: str, description: str, target_config: dict
) -> RedteamCampaign:
    """创建成员推理攻击活动并派发到 Celery。

    MIA 与普通红队的区别：不发攻击 prompt，而是发探针集统计响应差异。
    所以它用独立的 campaign 类型（strategy.source = "membership_inference"）。
    """
    from ..security.crypto import encrypt

    # API key 加密
    if target_config.get("api_key"):
        target_config = {**target_config, "api_key": encrypt(target_config["api_key"])}

    campaign = RedteamCampaign(
        name=name,
        description=description,
        target_config=json.dumps(target_config, ensure_ascii=False),
        strategy=json.dumps({"source": "membership_inference"}, ensure_ascii=False),
        status="pending",
    )
    session.add(campaign)
    await session.commit()
    await session.refresh(campaign)

    from ..scan.celery_app import celery_app

    async_result = celery_app.send_task("redteam.membership", args=[campaign.id])
    campaign.celery_task_id = async_result.id or ""
    await session.commit()
    return campaign


async def execute_mia(campaign_id: int) -> None:
    """执行成员推理攻击（由 Celery 调用）。"""
    from datetime import datetime

    from ..db import async_session

    async with async_session() as session:
        campaign = await session.get(RedteamCampaign, campaign_id)
        if not campaign:
            return

        target_config = json.loads(campaign.target_config or "{}")

        campaign.status = "running"
        campaign.started_at = datetime.utcnow()
        await session.commit()

        try:
            from ..security.crypto import decrypt

            api_key = target_config.get("api_key", "")
            if api_key.startswith("PLAIN:"):
                api_key = api_key[6:]
            elif api_key:
                try:
                    api_key = decrypt(api_key)
                except Exception:  # noqa: BLE001
                    pass

            from ..redteam.membership_inference import run_membership_inference
            from ..redteam.target_client import TargetClient

            target = TargetClient(
                base_url=target_config.get("base_url", "https://api.openai.com/v1"),
                api_key=api_key,
                model=target_config.get("model", "gpt-4o-mini"),
            )

            result = await run_membership_inference(target)

            # 把 MIA 结果写回 strategy（复用字段，避免改表）
            mia_result = {
                "source": "membership_inference",
                "mi_advantage": result.mi_advantage,
                "certainty_gap": round(result.certainty_gap, 4),
                "member_avg_certainty": round(result.member_avg_certainty, 4),
                "nonmember_avg_certainty": round(result.nonmember_avg_certainty, 4),
                "risk_level": result.risk_level,
                "interpretation": result.interpretation,
                "per_probe": result.per_probe[:20],  # 限制存储
            }
            campaign.strategy = json.dumps(mia_result, ensure_ascii=False)
            # 复用 ASR 字段存 MI Advantage（前端可统一展示）
            campaign.asr = result.mi_advantage
            campaign.total_attacks = len(result.per_probe)
            # MIA 没有"成功攻击"概念，用 risk_level 映射 success_count
            risk_to_count = {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
            }
            campaign.success_count = risk_to_count.get(result.risk_level, 0)
            campaign.progress = 100
            campaign.status = "completed"
            campaign.finished_at = datetime.utcnow()
            await session.commit()

        except Exception as e:  # noqa: BLE001
            campaign.status = "failed"
            campaign.error = str(e)[:500]
            campaign.finished_at = datetime.utcnow()
            await session.commit()


async def get_mia_result(session: AsyncSession, campaign_id: int) -> dict | None:
    """获取成员推理攻击结果。"""
    campaign = await session.get(RedteamCampaign, campaign_id)
    if not campaign:
        return None
    try:
        strategy = json.loads(campaign.strategy or "{}")
    except json.JSONDecodeError:
        strategy = {}
    if strategy.get("source") != "membership_inference":
        return None
    return {
        "campaign_id": campaign.id,
        "name": campaign.name,
        "status": campaign.status,
        "mi_advantage": strategy.get("mi_advantage", 0.0),
        "certainty_gap": strategy.get("certainty_gap", 0.0),
        "member_avg_certainty": strategy.get("member_avg_certainty", 0.0),
        "nonmember_avg_certainty": strategy.get("nonmember_avg_certainty", 0.0),
        "risk_level": strategy.get("risk_level", "low"),
        "interpretation": strategy.get("interpretation", ""),
        "per_probe": strategy.get("per_probe", []),
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
    }


# ==================== 训练数据导出（红队 → 安全微调数据飞轮） ====================


async def export_training_data(
    session: AsyncSession,
    campaign_id: int,
    fmt: str = "dpo",
    category: str | None = None,
) -> tuple[str, int]:
    """把红队攻击结果导出为训练数据 JSONL。

    - fmt="dpo"：成功攻击（模型屈服）→ 偏好对 {prompt, chosen, rejected, meta}
      chosen 为按类别合成的安全拒绝（多模板轮换），rejected 为目标模型真实屈服回复。
    - fmt="sft"：失败攻击（模型本就安全拒绝）→ {prompt, completion}（真实安全回复，
      格式兼容训练数据模块的 dataset_scanner，可回传扫描形成闭环）。

    返回 (jsonl 文本, 条数)。
    """
    import random

    from ..redteam.refusal_templates import pick_refusal

    rng = random.Random(campaign_id * 7919)

    stmt = (
        select(AttackResult, AttackCase)
        .join(AttackCase, AttackResult.case_id == AttackCase.id)
        .where(AttackResult.campaign_id == campaign_id)
    )
    if fmt == "dpo":
        stmt = stmt.where(AttackResult.success == 1)
    else:  # sft：失败攻击 = 真实安全回复
        stmt = stmt.where(AttackResult.success == 0)
    if category:
        stmt = stmt.where(AttackCase.category == category)
    stmt = stmt.order_by(AttackResult.id.asc())

    rows = (await session.execute(stmt)).all()

    lines: list[str] = []
    for attack_result, attack_case in rows:
        response = (attack_result.response or "").strip()
        prompt = (attack_case.prompt or "").strip()
        if not response or not prompt:
            continue  # 空回复（超时/空响应）不可用
        if fmt == "dpo":
            record = {
                "prompt": prompt,
                "chosen": pick_refusal(attack_case.category, rng),
                "rejected": response,
                "meta": {
                    "category": attack_case.category,
                    "campaign_id": campaign_id,
                    "case_id": attack_case.id,
                    "chosen_source": "synthetic",
                    "judged_category": attack_result.judged_category or "",
                },
            }
        else:
            record = {
                "prompt": prompt,
                "completion": response,
                "meta": {
                    "category": attack_case.category,
                    "campaign_id": campaign_id,
                    "case_id": attack_case.id,
                    "source": "real",
                },
            }
        lines.append(json.dumps(record, ensure_ascii=False))

    return "\n".join(lines) + ("\n" if lines else ""), len(lines)
