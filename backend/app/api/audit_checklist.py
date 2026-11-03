"""OWASP LLM Top 10 审计 checklist API 路由。

前缀 /api/audit-checklist，管理端鉴权。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..schemas.audit_checklist import (
    AuditChecklistItemOut,
    ChecklistSummary,
    ChecklistUpdateRequest,
)
from ..services import audit_checklist_service
from .deps import get_admin_identity

router = APIRouter(prefix="/audit-checklist", tags=["audit-checklist"])


@router.get("", response_model=list[AuditChecklistItemOut])
async def list_checklist(
    status: str | None = Query(None, description="按状态过滤：pending/pass/fail/na"),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    """列出 OWASP LLM Top 10 审计 checklist。"""
    items = await audit_checklist_service.list_checklist(session, status)
    return [AuditChecklistItemOut.from_orm_with_json(i) for i in items]


@router.get("/summary", response_model=ChecklistSummary)
async def get_summary(
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    """获取审计进度摘要（通过率）。"""
    s = await audit_checklist_service.get_checklist_summary(session)
    return ChecklistSummary(
        total=s["total"],
        pass_count=s["pass"],
        fail_count=s["fail"],
        pending_count=s["pending"],
        na_count=s["na"],
        pass_rate=s["pass_rate"],
    )


@router.put("/{item_id}", response_model=AuditChecklistItemOut)
async def update_item(
    item_id: int,
    req: ChecklistUpdateRequest,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    """更新 checklist 项的审计状态（通过/不通过/不适用）。"""
    try:
        item = await audit_checklist_service.update_checklist_item(
            session, item_id, req.status, req.evidence, req.auditor
        )
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if not item:
        raise HTTPException(404, "审计项不存在")
    return AuditChecklistItemOut.from_orm_with_json(item)
