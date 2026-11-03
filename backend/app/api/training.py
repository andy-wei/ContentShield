"""训练数据安全扫描 API 路由。

前缀 /api/training，管理端鉴权。
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..schemas.training import (
    DatasetCreate,
    DatasetFindingList,
    DatasetFindingOut,
    DatasetOut,
    DatasetScanOut,
    DatasetScanReport,
    DatasetScanSummary,
)
from ..services import training_service
from .deps import get_admin_identity

router = APIRouter(prefix="/training", tags=["training"])


# ==================== 数据集管理 ====================


@router.get("/datasets", response_model=list[DatasetOut])
async def list_datasets(
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await training_service.list_datasets(session)


@router.post("/datasets", response_model=DatasetOut, status_code=201)
async def upload_dataset(
    name: str = Form(...),
    format: str = Form("jsonl"),
    source: str = Form("internal"),
    version: str = Form(""),
    description: str = Form(""),
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    """上传数据集文件并创建记录。"""
    # 校验格式
    if format not in ("jsonl", "csv", "txt"):
        raise HTTPException(400, f"不支持的格式: {format}")

    # 保存文件
    upload_dir = os.path.join(settings.data_dir, "datasets")
    os.makedirs(upload_dir, exist_ok=True)
    safe_name = Path(file.filename or "dataset").name
    file_path = os.path.join("datasets", safe_name)
    full_path = os.path.join(settings.data_dir, file_path)

    # 避免覆盖
    if os.path.exists(full_path):
        base, ext = os.path.splitext(safe_name)
        file_path = os.path.join("datasets", f"{base}_{os.getpid()}{ext}")
        full_path = os.path.join(settings.data_dir, file_path)

    with open(full_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # 统计行数
    record_count = content.decode("utf-8", errors="replace").count("\n")
    if record_count == 0:
        record_count = 1

    data = DatasetCreate(
        name=name, description=description, format=format, source=source, version=version
    )
    dataset = await training_service.create_dataset(session, data, file_path, record_count)
    return dataset


@router.get("/datasets/{dataset_id}", response_model=DatasetOut)
async def get_dataset(
    dataset_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    dataset = await training_service.get_dataset(session, dataset_id)
    if not dataset:
        raise HTTPException(404, "数据集不存在")
    return dataset


@router.delete("/datasets/{dataset_id}")
async def delete_dataset(
    dataset_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    if not await training_service.delete_dataset(session, dataset_id):
        raise HTTPException(404, "数据集不存在")
    return {"ok": True}


# ==================== 扫描任务 ====================


@router.get("/scans", response_model=list[DatasetScanSummary])
async def list_scans(
    dataset_id: int | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    return await training_service.list_scans(session, dataset_id, limit, offset)


@router.post("/datasets/{dataset_id}/scan", response_model=DatasetScanOut, status_code=201)
async def create_scan(
    dataset_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    try:
        scan = await training_service.create_scan(session, dataset_id)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return DatasetScanOut.from_orm_with_stats(scan)


@router.get("/scans/{scan_id}", response_model=DatasetScanOut)
async def get_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    scan = await training_service.get_scan(session, scan_id)
    if not scan:
        raise HTTPException(404, "扫描任务不存在")
    return DatasetScanOut.from_orm_with_stats(scan)


# ==================== 问题样本查询 ====================


@router.get("/scans/{scan_id}/findings", response_model=DatasetFindingList)
async def list_findings(
    scan_id: int,
    issue_type: str | None = Query(None),
    poison_type: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    findings, issue_counts, total = await training_service.list_findings(
        session, scan_id, issue_type, poison_type, limit, offset
    )
    return DatasetFindingList(
        items=[DatasetFindingOut.from_orm_with_json(f) for f in findings],
        total=total,
        issue_counts=issue_counts,
    )


# ==================== 扫描报告 ====================


@router.get("/scans/{scan_id}/report", response_model=DatasetScanReport)
async def get_scan_report(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _admin=Depends(get_admin_identity),
):
    report = await training_service.get_scan_report(session, scan_id)
    if not report:
        raise HTTPException(404, "扫描任务不存在")
    return report
