"""模型供应链安全（MBOM）API 路由。

前缀 /api/mbom，管理端鉴权。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..schemas.mbom import (
    IntegrityCheckResult,
    MBOMExport,
    ModelArtifactCreate,
    ModelArtifactOut,
    ModelArtifactSummary,
    ModelDependencyCreate,
    ModelDependencyOut,
)
from ..services import mbom_service
from .deps import get_admin_identity

router = APIRouter(prefix="/mbom", tags=["mbom"])


# ==================== 制品管理 ====================


@router.get("/artifacts", response_model=list[ModelArtifactSummary])
async def list_artifacts(
    model_type: str | None = Query(None),
    source: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await mbom_service.list_artifacts(session, model_type, source)


@router.post("/artifacts", response_model=ModelArtifactOut, status_code=201)
async def create_artifact(
    data: ModelArtifactCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    artifact = await mbom_service.create_artifact(session, data)
    return ModelArtifactOut.from_orm_with_json(artifact)


@router.get("/artifacts/{artifact_id}", response_model=ModelArtifactOut)
async def get_artifact(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    artifact = await mbom_service.get_artifact(session, artifact_id)
    if not artifact:
        raise HTTPException(404, "模型制品不存在")
    return ModelArtifactOut.from_orm_with_json(artifact)


@router.put("/artifacts/{artifact_id}", response_model=ModelArtifactOut)
async def update_artifact(
    artifact_id: int,
    updates: dict,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    artifact = await mbom_service.update_artifact(session, artifact_id, updates)
    if not artifact:
        raise HTTPException(404, "模型制品不存在")
    return ModelArtifactOut.from_orm_with_json(artifact)


@router.delete("/artifacts/{artifact_id}")
async def delete_artifact(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    if not await mbom_service.delete_artifact(session, artifact_id):
        raise HTTPException(404, "模型制品不存在")
    return {"ok": True}


# ==================== 完整性校验 ====================


@router.post("/artifacts/{artifact_id}/verify", response_model=IntegrityCheckResult)
async def verify_artifact(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        return await mbom_service.check_integrity(session, artifact_id)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/artifacts/{artifact_id}/rehash")
async def rehash_artifact(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        new_hash = await mbom_service.recompute_hash(session, artifact_id)
        return {"sha256": new_hash}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


# ==================== 依赖管理 ====================


@router.get("/artifacts/{artifact_id}/dependencies", response_model=list[ModelDependencyOut])
async def list_dependencies(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await mbom_service.list_dependencies(session, artifact_id)


@router.post(
    "/artifacts/{artifact_id}/dependencies", response_model=ModelDependencyOut, status_code=201
)
async def add_dependency(
    artifact_id: int,
    data: ModelDependencyCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        return await mbom_service.add_dependency(session, artifact_id, data)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


# ==================== 风险评估 ====================


@router.get("/artifacts/{artifact_id}/risk")
async def get_risk(
    artifact_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        return await mbom_service.get_risk_assessment(session, artifact_id)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


# ==================== MBOM 导出 ====================


@router.get("/export", response_model=MBOMExport)
async def export_mbom(
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await mbom_service.export_mbom(session)
