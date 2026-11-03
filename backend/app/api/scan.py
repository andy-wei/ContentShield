"""DevSecOps 扫描平台 API 路由。

前缀 /api/scan，管理端鉴权（复用 get_admin_identity）。
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..schemas.scan import (
    FindingList,
    FindingOut,
    GateResult,
    ScanJobCreate,
    ScanJobOut,
    ScanJobSummary,
    ScanPolicyCreate,
    ScanPolicyOut,
    ScanTargetCreate,
    ScanTargetOut,
    ScanUploadRequest,
    ToolInfo,
)
from ..services import scan_service
from .deps import get_admin_identity

router = APIRouter(prefix="/scan", tags=["scan"])


# ==================== 扫描目标 ====================


@router.get("/targets", response_model=list[ScanTargetOut])
async def list_targets(
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await scan_service.list_targets(session)


@router.post("/targets", response_model=ScanTargetOut, status_code=201)
async def create_target(
    data: ScanTargetCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await scan_service.create_target(session, data)


@router.get("/targets/{target_id}", response_model=ScanTargetOut)
async def get_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    target = await scan_service.get_target(session, target_id)
    if not target:
        raise HTTPException(404, "扫描目标不存在")
    return target


@router.delete("/targets/{target_id}")
async def delete_target(
    target_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    if not await scan_service.delete_target(session, target_id):
        raise HTTPException(404, "扫描目标不存在")
    return {"ok": True}


# ==================== 扫描任务 ====================


@router.get("/jobs", response_model=list[ScanJobSummary])
async def list_jobs(
    target_id: int | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await scan_service.list_jobs(session, target_id, status, limit, offset)


@router.post("/jobs", response_model=ScanJobOut, status_code=201)
async def create_job(
    data: ScanJobCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        job = await scan_service.create_job(session, data)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return ScanJobOut.from_orm_with_tools(job)


@router.get("/jobs/{job_id}", response_model=ScanJobOut)
async def get_job(
    job_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    job = await scan_service.get_job(session, job_id)
    if not job:
        raise HTTPException(404, "扫描任务不存在")
    return ScanJobOut.from_orm_with_tools(job)


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(
    job_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    if not await scan_service.cancel_job(session, job_id):
        raise HTTPException(400, "任务不存在或已结束，无法取消")
    return {"ok": True}


# ==================== Finding 查询 ====================


@router.get("/jobs/{job_id}/findings", response_model=FindingList)
async def list_findings(
    job_id: int,
    severity: str | None = Query(None),
    tool: str | None = Query(None),
    category: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    findings, counts, total = await scan_service.list_findings(
        session, job_id, severity, tool, category, limit, offset
    )
    return FindingList(
        items=[FindingOut.model_validate(f) for f in findings],
        total=total,
        counts=counts,
    )


# ==================== 门禁策略 ====================


@router.get("/policies", response_model=list[ScanPolicyOut])
async def list_policies(
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await scan_service.list_policies(session)


@router.post("/policies", response_model=ScanPolicyOut, status_code=201)
async def create_policy(
    data: ScanPolicyCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await scan_service.upsert_policy(session, data)


@router.put("/policies/{policy_id}", response_model=ScanPolicyOut)
async def update_policy(
    policy_id: int,
    data: ScanPolicyCreate,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        return await scan_service.upsert_policy(session, data, policy_id)
    except ValueError as e:
        raise HTTPException(404, str(e)) from e


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    if not await scan_service.delete_policy(session, policy_id):
        raise HTTPException(404, "策略不存在")
    return {"ok": True}


# ==================== 门禁判定 ====================


@router.get("/jobs/{job_id}/gate", response_model=GateResult)
async def evaluate_gate(
    job_id: int,
    policy_id: int | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    job = await scan_service.get_job(session, job_id)
    if not job:
        raise HTTPException(404, "扫描任务不存在")
    return await scan_service.evaluate_gate(session, job_id, policy_id)


# ==================== 可用工具 ====================


@router.get("/tools", response_model=list[ToolInfo])
async def list_tools(
    _admin=Depends(get_admin_identity),
):
    return scan_service.list_tools()


# ==================== CI 上传（无鉴权或用简单 token）====================


@router.post("/upload", response_model=ScanJobOut, status_code=201)
async def upload_results(
    data: ScanUploadRequest,
    session: AsyncSession = Depends(get_session),
):
    """CI 端上传扫描结果。

    注：此端点免管理鉴权（CI 用单独的 upload token 或在内网环境调用）。
    生产应加 IP 白名单或独立 token。
    """
    job = await scan_service.upload_scan_results(session, data)
    return ScanJobOut.from_orm_with_tools(job)
