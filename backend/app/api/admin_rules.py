"""策略规则管理 API：类别开关、词库 CRUD、DLP 规则 CRUD。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..engine.orchestrator import orchestrator
from ..models import CategoryRule, DlpRule, LexiconEntry
from ..schemas.rule import (
    CategoryRuleRead,
    CategoryRuleUpdate,
    DlpRuleCreate,
    DlpRuleRead,
    LexiconEntryCreate,
    LexiconEntryRead,
)

router = APIRouter(prefix="/rules", tags=["admin"])


# ---- 类别 ----
@router.get("/categories", response_model=list[CategoryRuleRead])
async def list_categories(session: AsyncSession = Depends(get_session)):
    res = await session.execute(select(CategoryRule).order_by(CategoryRule.order))
    return res.scalars().all()


@router.patch("/categories/{code}", response_model=CategoryRuleRead)
async def update_category(
    code: str,
    update: CategoryRuleUpdate,
    session: AsyncSession = Depends(get_session),
):
    cat = await session.scalar(
        select(CategoryRule).where(CategoryRule.code == code)
    )
    if not cat:
        raise HTTPException(status_code=404, detail="category not found")
    for k, v in update.model_dump(exclude_unset=True).items():
        setattr(cat, k, v)
    await session.commit()
    await session.refresh(cat)
    await orchestrator.invalidate_caches()
    return cat


# ---- 词库 ----
@router.get("/lexicon", response_model=list[LexiconEntryRead])
async def list_lexicon(
    category: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(LexiconEntry).order_by(LexiconEntry.id.desc())
    if category:
        stmt = stmt.where(LexiconEntry.category == category)
    res = await session.execute(stmt)
    return res.scalars().all()


@router.post("/lexicon", response_model=LexiconEntryRead, status_code=201)
async def add_lexicon(
    entry: LexiconEntryCreate,
    session: AsyncSession = Depends(get_session),
):
    obj = LexiconEntry(**entry.model_dump())
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    await orchestrator.lexicon.invalidate()
    return obj


@router.delete("/lexicon/{entry_id}", status_code=204)
async def delete_lexicon(
    entry_id: int,
    session: AsyncSession = Depends(get_session),
):
    obj = await session.get(LexiconEntry, entry_id)
    if not obj:
        raise HTTPException(status_code=404, detail="not found")
    await session.delete(obj)
    await session.commit()
    await orchestrator.lexicon.invalidate()


# ---- DLP 规则 ----
@router.get("/dlp", response_model=list[DlpRuleRead])
async def list_dlp(session: AsyncSession = Depends(get_session)):
    res = await session.execute(select(DlpRule).order_by(DlpRule.id.desc()))
    return res.scalars().all()


@router.post("/dlp", response_model=DlpRuleRead, status_code=201)
async def add_dlp(
    rule: DlpRuleCreate,
    session: AsyncSession = Depends(get_session),
):
    import re

    try:
        re.compile(rule.pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"invalid regex: {e}")
    obj = DlpRule(**rule.model_dump())
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    await orchestrator.dlp.invalidate()
    return obj


@router.delete("/dlp/{rule_id}", status_code=204)
async def delete_dlp(
    rule_id: int,
    session: AsyncSession = Depends(get_session),
):
    obj = await session.get(DlpRule, rule_id)
    if not obj:
        raise HTTPException(status_code=404, detail="not found")
    await session.delete(obj)
    await session.commit()
    await orchestrator.dlp.invalidate()
