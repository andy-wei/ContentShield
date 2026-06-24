"""审计日志查询与 CSV 导出。"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models import AuditLog

router = APIRouter(prefix="/audit", tags=["admin"])


@router.get("")
async def list_audit(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    decision: str | None = None,
    source: str | None = None,
    days: int | None = None,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if decision:
        stmt = stmt.where(AuditLog.decision == decision)
    if source:
        stmt = stmt.where(AuditLog.source == source)
    if days:
        since = datetime.utcnow() - timedelta(days=days)
        stmt = stmt.where(AuditLog.created_at >= since)

    # 计算总数
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await session.execute(count_stmt)).scalar() or 0

    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    res = await session.execute(stmt)
    rows = res.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": r.id,
                "created_at": r.created_at.isoformat(),
                "source": r.source,
                "input_text": r.input_text[:200],
                "input_length": r.input_length,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "categories": r.categories,
                "explanations": r.explanations,
                "latency_ms": r.latency_ms,
                "principal_id": r.principal_id,
                "subject": r.subject,
                "scopes": r.scopes,
            }
            for r in rows
        ],
    }


@router.get("/{log_id}")
async def get_audit(log_id: int, session: AsyncSession = Depends(get_session)):
    log = await session.get(AuditLog, log_id)
    if not log:
        raise HTTPException(status_code=404, detail="not found")
    return {
        "id": log.id,
        "created_at": log.created_at.isoformat(),
        "source": log.source,
        "input_text": log.input_text,
        "input_length": log.input_length,
        "decision": log.decision,
        "risk_score": log.risk_score,
        "categories": log.categories,
        "layers": log.layers,
        "explanations": log.explanations,
        "latency_ms": log.latency_ms,
        "gateway_response": log.gateway_response,
    }


@router.get("/export/csv")
async def export_csv(
    days: int = Query(settings.stats_lookback_days, ge=1, le=365),
    session: AsyncSession = Depends(get_session),
):
    since = datetime.utcnow() - timedelta(days=days)
    stmt = (
        select(AuditLog)
        .where(AuditLog.created_at >= since)
        .order_by(AuditLog.id.desc())
        .limit(10000)
    )
    res = await session.execute(stmt)
    rows = res.scalars().all()

    buf = io.StringIO()
    buf.write("\ufeff")  # BOM for Excel
    writer = csv.writer(buf)
    writer.writerow(
        ["id", "created_at", "source", "decision", "risk_score", "categories", "latency_ms", "input"]
    )
    for r in rows:
        writer.writerow(
            [
                r.id,
                r.created_at.isoformat(),
                r.source,
                r.decision,
                r.risk_score,
                ",".join(r.categories or []),
                r.latency_ms,
                r.input_text[:500],
            ]
        )

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=audit_{datetime.utcnow().date()}.csv"
        },
    )
