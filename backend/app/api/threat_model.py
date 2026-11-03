"""威胁建模管理 API。

端点分组：
  项目  GET/POST /projects, GET/PUT/DELETE /projects/{id}
  资产  GET/POST /projects/{id}/assets, PUT/DELETE /assets/{id}
  威胁  GET /projects/{id}/threats, POST /threats, PUT/DELETE /threats/{id},
        PATCH /threats/{id}/status
  生成  POST /projects/{id}/generate          （LLM 自动生成威胁）
  控制  GET/POST /threats/{id}/controls, PUT/DELETE /controls/{id}
  证据  GET /threats/{id}/evidence            （轻量联动：实际拦截数据）
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models.threat_model import Asset, MitigationControl, Threat, ThreatProject
from ..schemas.threat_model import (
    AssetCreate,
    AssetRead,
    AssetUpdate,
    ControlCreate,
    ControlRead,
    ControlUpdate,
    GenerateRequest,
    GenerateResponse,
    ThreatCreate,
    ThreatEvidenceResponse,
    ThreatProjectCreate,
    ThreatProjectRead,
    ThreatProjectUpdate,
    ThreatProjectWithStats,
    ThreatRead,
    ThreatStatusUpdate,
    ThreatUpdate,
)
from ..services.threat_model_service import compute_risk_level, threat_model_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threat-model", tags=["admin"])


# =====================================================================
# 项目
# =====================================================================
@router.get("/projects", response_model=list[ThreatProjectWithStats])
async def list_projects(session: AsyncSession = Depends(get_session)):
    res = await session.execute(select(ThreatProject).order_by(ThreatProject.id.desc()))
    projects = res.scalars().all()
    out: list[ThreatProjectWithStats] = []
    for p in projects:
        # 聚合统计
        asset_cnt = (
            await session.scalar(
                select(func.count()).select_from(Asset).where(Asset.project_id == p.id)
            )
            or 0
        )
        threat_cnt = (
            await session.scalar(
                select(func.count()).select_from(Threat).where(Threat.project_id == p.id)
            )
            or 0
        )
        open_cnt = (
            await session.scalar(
                select(func.count())
                .select_from(Threat)
                .where(Threat.project_id == p.id, Threat.status == "open")
            )
            or 0
        )
        crit_cnt = (
            await session.scalar(
                select(func.count())
                .select_from(Threat)
                .where(Threat.project_id == p.id, Threat.risk_level == "Critical")
            )
            or 0
        )
        out.append(
            ThreatProjectWithStats(
                id=p.id,
                name=p.name,
                description=p.description,
                status=p.status,
                created_at=p.created_at,
                updated_at=p.updated_at,
                asset_count=asset_cnt,
                threat_count=threat_cnt,
                open_count=open_cnt,
                critical_count=crit_cnt,
            )
        )
    return out


@router.post("/projects", response_model=ThreatProjectRead, status_code=201)
async def create_project(req: ThreatProjectCreate, session: AsyncSession = Depends(get_session)):
    project = ThreatProject(name=req.name, description=req.description, status=req.status)
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


@router.get("/projects/{project_id}", response_model=ThreatProjectRead)
async def get_project(project_id: int, session: AsyncSession = Depends(get_session)):
    project = await session.get(ThreatProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    return project


@router.put("/projects/{project_id}", response_model=ThreatProjectRead)
async def update_project(
    project_id: int,
    req: ThreatProjectUpdate,
    session: AsyncSession = Depends(get_session),
):
    project = await session.get(ThreatProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    for field, val in req.model_dump(exclude_unset=True).items():
        setattr(project, field, val)
    await session.commit()
    await session.refresh(project)
    return project


@router.delete("/projects/{project_id}", status_code=204)
async def delete_project(project_id: int, session: AsyncSession = Depends(get_session)):
    project = await session.get(ThreatProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    await session.delete(project)
    await session.commit()


# =====================================================================
# 资产
# =====================================================================
def _asset_to_read(a: Asset) -> AssetRead:
    import json as _json

    try:
        tech = _json.loads(a.tech_stack) if a.tech_stack else []
    except (ValueError, TypeError):
        tech = []
    try:
        props = _json.loads(a.properties) if a.properties else {}
    except (ValueError, TypeError):
        props = {}
    return AssetRead(
        id=a.id,
        project_id=a.project_id,
        name=a.name,
        description=a.description,
        asset_type=a.asset_type,
        tech_stack=tech,
        properties=props,
        created_at=a.created_at,
    )


@router.get("/projects/{project_id}/assets", response_model=list[AssetRead])
async def list_assets(project_id: int, session: AsyncSession = Depends(get_session)):
    res = await session.execute(
        select(Asset).where(Asset.project_id == project_id).order_by(Asset.id)
    )
    return [_asset_to_read(a) for a in res.scalars().all()]


@router.post("/projects/{project_id}/assets", response_model=AssetRead, status_code=201)
async def create_asset(
    project_id: int, req: AssetCreate, session: AsyncSession = Depends(get_session)
):
    import json as _json

    project = await session.get(ThreatProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    asset = Asset(
        project_id=project_id,
        name=req.name,
        description=req.description,
        asset_type=req.asset_type,
        tech_stack=_json.dumps(req.tech_stack, ensure_ascii=False),
        properties=_json.dumps(req.properties, ensure_ascii=False),
    )
    session.add(asset)
    await session.commit()
    await session.refresh(asset)
    return _asset_to_read(asset)


@router.put("/assets/{asset_id}", response_model=AssetRead)
async def update_asset(
    asset_id: int, req: AssetUpdate, session: AsyncSession = Depends(get_session)
):
    import json as _json

    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    data = req.model_dump(exclude_unset=True)
    if "tech_stack" in data:
        asset.tech_stack = _json.dumps(data.pop("tech_stack"), ensure_ascii=False)
    if "properties" in data:
        asset.properties = _json.dumps(data.pop("properties"), ensure_ascii=False)
    for field, val in data.items():
        setattr(asset, field, val)
    await session.commit()
    await session.refresh(asset)
    return _asset_to_read(asset)


@router.delete("/assets/{asset_id}", status_code=204)
async def delete_asset(asset_id: int, session: AsyncSession = Depends(get_session)):
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    await session.delete(asset)
    await session.commit()


# =====================================================================
# 威胁
# =====================================================================
@router.get("/projects/{project_id}/threats", response_model=list[ThreatRead])
async def list_threats(
    project_id: int,
    session: AsyncSession = Depends(get_session),
    status: str | None = Query(None),
    category: str | None = Query(None),
    risk_level: str | None = Query(None),
):
    stmt = select(Threat).where(Threat.project_id == project_id)
    if status:
        stmt = stmt.where(Threat.status == status)
    if category:
        stmt = stmt.where(Threat.category == category)
    if risk_level:
        stmt = stmt.where(Threat.risk_level == risk_level)
    stmt = stmt.order_by(Threat.id.desc())
    res = await session.execute(stmt)
    return res.scalars().all()


@router.post("/threats", response_model=ThreatRead, status_code=201)
async def create_threat(req: ThreatCreate, session: AsyncSession = Depends(get_session)):
    risk_level = compute_risk_level(req.likelihood, req.impact)
    threat = Threat(
        project_id=req.project_id,
        asset_id=req.asset_id,
        title=req.title,
        description=req.description,
        category=req.category,
        likelihood=req.likelihood,
        impact=req.impact,
        risk_level=risk_level,
        mitigation=req.mitigation,
        status=req.status,
        source=req.source,
    )
    session.add(threat)
    await session.commit()
    await session.refresh(threat)
    return threat


@router.put("/threats/{threat_id}", response_model=ThreatRead)
async def update_threat(
    threat_id: int, req: ThreatUpdate, session: AsyncSession = Depends(get_session)
):
    threat = await session.get(Threat, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="威胁不存在")
    data = req.model_dump(exclude_unset=True)
    for field, val in data.items():
        setattr(threat, field, val)
    # 评分变化时重算风险等级
    threat.risk_level = compute_risk_level(threat.likelihood, threat.impact)
    await session.commit()
    await session.refresh(threat)
    return threat


@router.patch("/threats/{threat_id}/status", response_model=ThreatRead)
async def update_threat_status(
    threat_id: int,
    req: ThreatStatusUpdate,
    session: AsyncSession = Depends(get_session),
):
    threat = await session.get(Threat, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="威胁不存在")
    threat.status = req.status
    await session.commit()
    await session.refresh(threat)
    return threat


@router.delete("/threats/{threat_id}", status_code=204)
async def delete_threat(threat_id: int, session: AsyncSession = Depends(get_session)):
    threat = await session.get(Threat, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="威胁不存在")
    await session.delete(threat)
    await session.commit()


# =====================================================================
# LLM 生成
# =====================================================================
@router.post("/projects/{project_id}/generate", response_model=GenerateResponse)
async def generate_threats(
    project_id: int,
    req: GenerateRequest,
    session: AsyncSession = Depends(get_session),
):
    """调用 LLM 为项目生成威胁清单。"""
    project = await session.get(ThreatProject, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # force_regenerate=True 时清空旧的 LLM 威胁（保留手工录入的）
    if req.force_regenerate:
        await session.execute(
            delete(Threat).where(Threat.project_id == project_id, Threat.source == "llm_generated")
        )
        await session.commit()

    # 加载资产
    res = await session.execute(
        select(Asset).where(Asset.project_id == project_id).order_by(Asset.id)
    )
    assets = res.scalars().all()

    try:
        created = await threat_model_service.generate_threats(session, project, assets)
    except RuntimeError as e:
        # 未配置或 LLM 调用失败 → 503
        raise HTTPException(status_code=503, detail=str(e)) from e

    return GenerateResponse(
        success=True,
        generated=len(created),
        threats=created,
        detail=f"LLM 生成 {len(created)} 条威胁",
    )


# =====================================================================
# 缓解控制
# =====================================================================
@router.get("/threats/{threat_id}/controls", response_model=list[ControlRead])
async def list_controls(threat_id: int, session: AsyncSession = Depends(get_session)):
    res = await session.execute(
        select(MitigationControl)
        .where(MitigationControl.threat_id == threat_id)
        .order_by(MitigationControl.id)
    )
    return res.scalars().all()


@router.post("/threats/{threat_id}/controls", response_model=ControlRead, status_code=201)
async def create_control(
    threat_id: int,
    req: ControlCreate,
    session: AsyncSession = Depends(get_session),
):
    threat = await session.get(Threat, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="威胁不存在")
    control = MitigationControl(
        threat_id=threat_id,
        control_type=req.control_type,
        ref_layer=req.ref_layer,
        ref_id=req.ref_id,
        description=req.description,
        effectiveness=req.effectiveness,
    )
    session.add(control)
    await session.commit()
    await session.refresh(control)
    return control


@router.put("/controls/{control_id}", response_model=ControlRead)
async def update_control(
    control_id: int,
    req: ControlUpdate,
    session: AsyncSession = Depends(get_session),
):
    control = await session.get(MitigationControl, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="控制不存在")
    for field, val in req.model_dump(exclude_unset=True).items():
        setattr(control, field, val)
    await session.commit()
    await session.refresh(control)
    return control


@router.delete("/controls/{control_id}", status_code=204)
async def delete_control(control_id: int, session: AsyncSession = Depends(get_session)):
    control = await session.get(MitigationControl, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="控制不存在")
    await session.delete(control)
    await session.commit()


# =====================================================================
# 证据（轻量联动核心）
# =====================================================================
@router.get("/threats/{threat_id}/evidence", response_model=ThreatEvidenceResponse)
async def get_threat_evidence(threat_id: int, session: AsyncSession = Depends(get_session)):
    """查询威胁关联控制的实际拦截证据。"""
    threat = await session.get(Threat, threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="威胁不存在")
    res = await session.execute(
        select(MitigationControl)
        .where(MitigationControl.threat_id == threat_id)
        .order_by(MitigationControl.id)
    )
    controls = res.scalars().all()
    evidence = await threat_model_service.get_evidence(session, threat, controls)
    return ThreatEvidenceResponse(threat_id=threat_id, controls=evidence)
