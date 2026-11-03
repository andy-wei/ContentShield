"""训练数据安全扫描服务：数据集管理 + 扫描任务 + 报告查询。"""

from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..models.training import Dataset, DatasetFinding, DatasetScan
from ..schemas.training import (
    DatasetCreate,
    DatasetFindingOut,
    DatasetOut,
    DatasetScanOut,
    DatasetScanReport,
    DatasetScanSummary,
)

# ==================== 数据集管理 ====================


async def create_dataset(
    session: AsyncSession, data: DatasetCreate, file_path: str, record_count: int
) -> Dataset:
    dataset = Dataset(
        name=data.name,
        description=data.description,
        format=data.format,
        source=data.source,
        version=data.version,
        file_path=file_path,
        record_count=record_count,
    )
    session.add(dataset)
    await session.commit()
    await session.refresh(dataset)
    return dataset


async def list_datasets(session: AsyncSession) -> list[Dataset]:
    result = await session.execute(select(Dataset).order_by(Dataset.created_at.desc()))
    return list(result.scalars().all())


async def get_dataset(session: AsyncSession, dataset_id: int) -> Dataset | None:
    return await session.get(Dataset, dataset_id)


async def delete_dataset(session: AsyncSession, dataset_id: int) -> bool:
    dataset = await session.get(Dataset, dataset_id)
    if not dataset:
        return False
    # 删除关联文件
    if dataset.file_path:
        full_path = os.path.join(settings.data_dir, dataset.file_path)
        if os.path.exists(full_path):
            os.remove(full_path)
    await session.delete(dataset)
    await session.commit()
    return True


# ==================== 扫描任务 ====================


async def create_scan(session: AsyncSession, dataset_id: int) -> DatasetScan:
    """创建扫描任务并派发到 Celery。"""
    dataset = await session.get(Dataset, dataset_id)
    if not dataset:
        raise ValueError(f"数据集 {dataset_id} 不存在")

    scan = DatasetScan(
        dataset_id=dataset_id,
        status="pending",
    )
    session.add(scan)
    await session.commit()
    await session.refresh(scan)

    # 派发到 Celery
    from ..scan.celery_app import celery_app

    celery_app.send_task("training.scan", args=[scan.id])
    return scan


async def list_scans(
    session: AsyncSession,
    dataset_id: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[DatasetScanSummary]:
    """列出扫描任务（含数据集名称）。"""
    stmt = (
        select(
            DatasetScan,
            Dataset.name.label("dataset_name"),
        )
        .join(Dataset, DatasetScan.dataset_id == Dataset.id)
        .order_by(DatasetScan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if dataset_id:
        stmt = stmt.where(DatasetScan.dataset_id == dataset_id)

    result = await session.execute(stmt)
    summaries = []
    for scan, dataset_name in result.all():
        try:
            stats = json.loads(scan.stats or "{}")
        except json.JSONDecodeError:
            stats = {}
        summaries.append(
            DatasetScanSummary(
                id=scan.id,
                dataset_id=scan.dataset_id,
                dataset_name=dataset_name,
                status=scan.status,  # type: ignore[arg-type]
                scanned_count=scan.scanned_count,
                flagged_count=scan.flagged_count,
                stats=stats,
                progress=scan.progress,
                started_at=scan.started_at,
                finished_at=scan.finished_at,
                created_at=scan.created_at,
            )
        )
    return summaries


async def get_scan(session: AsyncSession, scan_id: int) -> DatasetScan | None:
    return await session.get(DatasetScan, scan_id)


# ==================== 问题样本查询 ====================


async def list_findings(
    session: AsyncSession,
    scan_id: int,
    issue_type: str | None = None,
    poison_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[DatasetFinding], dict[str, int], int]:
    """查询某次扫描的问题样本。"""
    conditions = [DatasetFinding.scan_id == scan_id]
    if poison_type:
        conditions.append(DatasetFinding.poison_type == poison_type)

    # 总数
    count_stmt = select(func.count()).select_from(DatasetFinding).where(*conditions)
    total = (await session.execute(count_stmt)).scalar() or 0

    # 分页查询（按风险评分降序）
    stmt = (
        select(DatasetFinding)
        .where(*conditions)
        .order_by(DatasetFinding.risk_score.desc(), DatasetFinding.record_idx.asc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    findings = list(result.scalars().all())

    # 按 issue_type 统计（issue_types 是 JSON 字符串，SQLite 无法直接聚合，用 Python 统计）
    issue_counts: dict[str, int] = {}
    all_findings_stmt = select(DatasetFinding.issue_types, DatasetFinding.poison_type).where(
        DatasetFinding.scan_id == scan_id
    )
    all_result = await session.execute(all_findings_stmt)
    for issue_types_json, ptype in all_result.all():
        try:
            types = json.loads(issue_types_json or "[]")
            for t in types:
                issue_counts[t] = issue_counts.get(t, 0) + 1
        except json.JSONDecodeError:
            pass
        if ptype:
            issue_counts["poison"] = issue_counts.get("poison", 0) + 1

    # 按 issue_type 过滤（Python 层，因为 issue_types 是 JSON）
    if issue_type:
        filtered = []
        for f in findings:
            try:
                types = json.loads(f.issue_types or "[]")
                if issue_type in types or (issue_type == "poison" and f.poison_type):
                    filtered.append(f)
            except json.JSONDecodeError:
                pass
        findings = filtered

    return findings, issue_counts, total


# ==================== 扫描报告 ====================


async def get_scan_report(session: AsyncSession, scan_id: int) -> DatasetScanReport | None:
    """获取扫描汇总报告。"""
    scan = await session.get(DatasetScan, scan_id)
    if not scan:
        return None
    dataset = await session.get(Dataset, scan.dataset_id)
    if not dataset:
        return None

    # 风险评分分布
    risk_dist_stmt = select(DatasetFinding.risk_score).where(DatasetFinding.scan_id == scan_id)
    risk_scores = [r[0] for r in (await session.execute(risk_dist_stmt)).all()]
    risk_distribution = {
        "high (≥0.66)": sum(1 for r in risk_scores if r >= 0.66),
        "medium (0.33-0.65)": sum(1 for r in risk_scores if 0.33 <= r < 0.66),
        "low (<0.33)": sum(1 for r in risk_scores if r < 0.33),
    }

    # 投毒嫌疑数
    poison_count_stmt = (
        select(func.count())
        .select_from(DatasetFinding)
        .where(
            DatasetFinding.scan_id == scan_id,
            DatasetFinding.poison_type != "",
        )
    )
    poison_count = (await session.execute(poison_count_stmt)).scalar() or 0

    # 问题分布
    try:
        stats = json.loads(scan.stats or "{}")
    except json.JSONDecodeError:
        stats = {}

    # Top 5 最严重
    top_stmt = (
        select(DatasetFinding)
        .where(DatasetFinding.scan_id == scan_id)
        .order_by(DatasetFinding.risk_score.desc())
        .limit(5)
    )
    top_findings = list((await session.execute(top_stmt)).scalars().all())

    return DatasetScanReport(
        scan=DatasetScanOut.from_orm_with_stats(scan),
        dataset=DatasetOut.model_validate(dataset),
        issue_distribution=stats,
        poison_suspect_count=poison_count,
        risk_distribution=risk_distribution,
        top_findings=[DatasetFindingOut.from_orm_with_json(f) for f in top_findings],
    )


# ==================== 扫描执行（被 Celery 调用）====================


async def execute_scan(scan_id: int) -> None:
    """执行数据集扫描（异步，由 Celery task 调用）。

    复用运行时 orchestrator + 投毒检测。
    """
    from ..db import async_session
    from ..engine.orchestrator import orchestrator
    from ..training.dataset_scanner import read_records, scan_dataset

    async with async_session() as session:
        scan = await session.get(DatasetScan, scan_id)
        if not scan:
            return
        dataset = await session.get(Dataset, scan.dataset_id)
        if not dataset:
            scan.status = "failed"
            scan.error = "数据集不存在"
            scan.finished_at = datetime.utcnow()
            await session.commit()
            return

        # 标记运行中
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 0
        await session.commit()

        try:
            # 读取数据集
            full_path = os.path.join(settings.data_dir, dataset.file_path)
            records = read_records(full_path, dataset.format)
            scan.scanned_count = len(records)
            await session.commit()

            # 批量扫描（带进度回调）
            def on_progress(scanned, total):
                scan.progress = int(scanned / total * 100) if total else 100

            flagged_results = await scan_dataset(
                records, orchestrator, batch_size=20, on_progress=on_progress
            )

            # 落库问题样本
            issue_counts: dict[str, int] = {}
            for r in flagged_results:
                # 统计
                for t in r.issue_types:
                    issue_counts[t] = issue_counts.get(t, 0) + 1

                finding = DatasetFinding(
                    scan_id=scan.id,
                    record_idx=r.record_idx,
                    record_hash=r.record_hash,
                    issue_types=json.dumps(r.issue_types),
                    decision=r.decision,
                    risk_score=r.risk_score,
                    layers=json.dumps(r.layers, ensure_ascii=False),
                    categories=json.dumps(r.categories, ensure_ascii=False),
                    poison_type=r.poison_type,
                    preview=r.preview,
                )
                session.add(finding)

            scan.flagged_count = len(flagged_results)
            scan.stats = json.dumps(issue_counts, ensure_ascii=False)
            scan.progress = 100
            scan.status = "completed"
            scan.finished_at = datetime.utcnow()
            await session.commit()

        except Exception as e:  # noqa: BLE001
            scan.status = "failed"
            scan.error = str(e)[:500]
            scan.finished_at = datetime.utcnow()
            await session.commit()
            raise
