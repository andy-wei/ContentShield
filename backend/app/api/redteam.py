"""LLM 红队对抗测试 API 路由。

前缀 /api/redteam，管理端鉴权。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..schemas.redteam import (
    AttackResultList,
    AttackResultOut,
    CampaignCreate,
    CampaignOut,
    CampaignReport,
)
from ..services import redteam_service
from .deps import get_admin_identity

router = APIRouter(prefix="/redteam", tags=["redteam"])


# ==================== Campaign 管理 ====================


@router.get("/campaigns", response_model=list[CampaignOut])
async def list_campaigns(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await redteam_service.list_campaigns(session, limit, offset)


@router.post("/campaigns", response_model=CampaignOut, status_code=201)
async def create_campaign(
    data: CampaignCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    campaign = await redteam_service.create_campaign(session, data)
    return CampaignOut.from_orm_with_json(campaign)


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
async def get_campaign(
    campaign_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    campaign = await redteam_service.get_campaign(session, campaign_id)
    if not campaign:
        raise HTTPException(404, "红队活动不存在")
    return campaign


@router.delete("/campaigns/{campaign_id}")
async def delete_campaign(
    campaign_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    if not await redteam_service.delete_campaign(session, campaign_id):
        raise HTTPException(404, "红队活动不存在")
    return {"ok": True}


# ==================== 结果查询 ====================


@router.get("/campaigns/{campaign_id}/results", response_model=AttackResultList)
async def list_results(
    campaign_id: int,
    success_only: bool = Query(False),
    category: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    results, category_stats, total = await redteam_service.list_results(
        session, campaign_id, success_only, category, limit, offset
    )
    items = []
    for attack_result, attack_case in results:
        items.append(
            AttackResultOut(
                id=attack_result.id,
                case_id=attack_result.case_id,
                campaign_id=attack_result.campaign_id,
                response=attack_result.response,
                judged_unsafe=bool(attack_result.judged_unsafe),
                judged_category=attack_result.judged_category,
                judge_raw=attack_result.judge_raw,
                latency_ms=attack_result.latency_ms,
                success=bool(attack_result.success),
                error=attack_result.error,
                created_at=attack_result.created_at,
                case={
                    "id": attack_case.id,
                    "campaign_id": attack_case.campaign_id,
                    "prompt": attack_case.prompt,
                    "source": attack_case.source,
                    "category": attack_case.category,
                    "template_name": attack_case.template_name,
                    "created_at": attack_case.created_at,
                },
            )
        )
    return AttackResultList(items=items, total=total, category_stats=category_stats)


# ==================== 报告 ====================


@router.get("/campaigns/{campaign_id}/report", response_model=CampaignReport)
async def get_report(
    campaign_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    report = await redteam_service.get_report(session, campaign_id)
    if not report:
        raise HTTPException(404, "红队活动不存在")
    return report


# ==================== 成员推理攻击（MIA）====================


class MIACreateRequest(BaseModel):
    """成员推理攻击请求。"""

    name: str
    description: str = ""
    target_base_url: str = "https://api.openai.com/v1"
    target_api_key: str = ""
    target_model: str = "gpt-4o-mini"


@router.post("/membership-inference", status_code=201)
async def create_mia(
    req: MIACreateRequest,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    """发起成员推理攻击（评估模型是否泄露训练数据成员关系）。"""
    campaign = await redteam_service.create_mia_campaign(
        session,
        name=req.name,
        description=req.description,
        target_config={
            "base_url": req.target_base_url,
            "api_key": req.target_api_key,
            "model": req.target_model,
        },
    )
    return {"campaign_id": campaign.id, "status": campaign.status}


@router.get("/membership-inference/{campaign_id}")
async def get_mia(
    campaign_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    """获取成员推理攻击结果。"""
    result = await redteam_service.get_mia_result(session, campaign_id)
    if result is None:
        raise HTTPException(404, "MIA 活动不存在或非 MIA 类型")
    return result
