"""仪表盘统计：检测数、拦截率、趋势、类别分布。"""
from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models import AuditLog

router = APIRouter(prefix="/stats", tags=["admin"])


@router.get("/overview")
async def overview(
    days: int = Query(settings.stats_lookback_days, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.utcnow() - timedelta(days=days)

    # 总数
    total = await session.scalar(
        select(func.count()).where(AuditLog.created_at >= since)
    ) or 0

    # 各决策数
    dec_res = await session.execute(
        select(AuditLog.decision, func.count())
        .where(AuditLog.created_at >= since)
        .group_by(AuditLog.decision)
    )
    decision_counts = {k: v for k, v in dec_res.all()}
    blocked = decision_counts.get("block", 0)
    warned = decision_counts.get("warn", 0)
    passed = decision_counts.get("pass", 0)
    block_rate = round(blocked / total, 4) if total else 0.0

    # 平均延迟与风险
    avg_latency = await session.scalar(
        select(func.avg(AuditLog.latency_ms)).where(AuditLog.created_at >= since)
    )
    avg_risk = await session.scalar(
        select(func.avg(AuditLog.risk_score)).where(AuditLog.created_at >= since)
    )

    return {
        "days": days,
        "total": total,
        "blocked": blocked,
        "warned": warned,
        "passed": passed,
        "block_rate": block_rate,
        "avg_latency_ms": round(avg_latency or 0, 1),
        "avg_risk_score": round(avg_risk or 0, 4),
    }


@router.get("/trend")
async def trend(
    days: int = Query(7, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
):
    """按天聚合的检测量与拦截量趋势。"""
    since = datetime.utcnow() - timedelta(days=days)
    # SQLite 用 date()；PostgreSQL 用 date_trunc。这里用 Python 聚合，兼容两者
    res = await session.execute(
        select(
            AuditLog.created_at,
            AuditLog.decision,
        ).where(AuditLog.created_at >= since)
    )
    rows = res.all()

    buckets: dict[str, dict] = {}
    for created_at, decision in rows:
        day = created_at.date().isoformat()
        b = buckets.setdefault(day, {"date": day, "total": 0, "blocked": 0, "warned": 0})
        b["total"] += 1
        if decision == "block":
            b["blocked"] += 1
        elif decision == "warn":
            b["warned"] += 1

    return sorted(buckets.values(), key=lambda x: x["date"])


@router.get("/categories")
async def category_distribution(
    days: int = Query(settings.stats_lookback_days, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
):
    """命中类别分布（Top N）。"""
    since = datetime.utcnow() - timedelta(days=days)
    res = await session.execute(
        select(AuditLog.categories).where(AuditLog.created_at >= since)
    )
    counts: dict[str, int] = {}
    for (cats,) in res.all():
        for c in cats or []:
            counts[c] = counts.get(c, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:20]
    return [{"category": k, "count": v} for k, v in items]


@router.get("/layers")
async def layer_distribution(
    days: int = Query(settings.stats_lookback_days, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
):
    """各层命中分布。"""
    since = datetime.utcnow() - timedelta(days=days)
    res = await session.execute(
        select(AuditLog.layers).where(AuditLog.created_at >= since)
    )
    counts: dict[str, int] = {
        "lexicon": 0,
        "prompt_guard": 0,
        "llama_guard": 0,
        "dlp": 0,
    }
    for (layers,) in res.all():
        if not isinstance(layers, dict):
            continue
        for name, detail in layers.items():
            if isinstance(detail, dict) and detail.get("hit"):
                counts[name] = counts.get(name, 0) + 1
    return [{"layer": k, "count": v} for k, v in counts.items()]
