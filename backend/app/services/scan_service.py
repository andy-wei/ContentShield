"""扫描服务：封装扫描目标/任务/策略的 DB 操作 + Celery 派发。

API 层调用本服务，不直接操作 ORM/Celery。
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.scan import Finding, ScanJob, ScanPolicy, ScanTarget
from ..schemas.scan import (
    GateResult,
    ScanJobCreate,
    ScanJobSummary,
    ScanPolicyCreate,
    ScanTargetCreate,
    ScanUploadRequest,
)

# ==================== 扫描目标 ====================


async def create_target(session: AsyncSession, data: ScanTargetCreate) -> ScanTarget:
    target = ScanTarget(
        name=data.name,
        target_type=data.target_type,
        location=data.location,
        ref=data.ref,
    )
    session.add(target)
    await session.commit()
    await session.refresh(target)
    return target


async def list_targets(session: AsyncSession) -> list[ScanTarget]:
    result = await session.execute(select(ScanTarget).order_by(ScanTarget.created_at.desc()))
    return list(result.scalars().all())


async def get_target(session: AsyncSession, target_id: int) -> ScanTarget | None:
    return await session.get(ScanTarget, target_id)


async def delete_target(session: AsyncSession, target_id: int) -> bool:
    target = await session.get(ScanTarget, target_id)
    if not target:
        return False
    await session.delete(target)
    await session.commit()
    return True


# ==================== 扫描任务 ====================


async def create_job(session: AsyncSession, data: ScanJobCreate) -> ScanJob:
    """创建扫描任务并派发到 Celery。"""
    target = await session.get(ScanTarget, data.target_id)
    if not target:
        raise ValueError(f"扫描目标 {data.target_id} 不存在")

    job = ScanJob(
        target_id=data.target_id,
        trigger=data.trigger,
        tools=json.dumps(data.tools),
        status="pending",
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    # 派发到 Celery（延迟导入避免循环依赖）
    from ..scan.tasks import run_scan_task

    async_result = run_scan_task.delay(job.id)
    # 立即把 celery_task_id 写回
    job.celery_task_id = async_result.id or ""
    await session.commit()
    return job


async def list_jobs(
    session: AsyncSession,
    target_id: int | None = None,
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[ScanJobSummary]:
    """列出扫描任务（含 target 名称）。"""
    stmt = (
        select(
            ScanJob,
            ScanTarget.name.label("target_name"),
        )
        .join(ScanTarget, ScanJob.target_id == ScanTarget.id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if target_id:
        stmt = stmt.where(ScanJob.target_id == target_id)
    if status:
        stmt = stmt.where(ScanJob.status == status)

    result = await session.execute(stmt)
    rows = result.all()
    summaries = []
    for job, target_name in rows:
        try:
            tools = json.loads(job.tools or "[]")
        except json.JSONDecodeError:
            tools = []
        summaries.append(
            ScanJobSummary(
                id=job.id,
                target_id=job.target_id,
                target_name=target_name,
                trigger=job.trigger,  # type: ignore[arg-type]
                tools=tools,
                status=job.status,  # type: ignore[arg-type]
                progress=job.progress,
                commit=job.commit,
                critical_count=job.critical_count,
                high_count=job.high_count,
                medium_count=job.medium_count,
                low_count=job.low_count,
                info_count=job.info_count,
                started_at=job.started_at,
                finished_at=job.finished_at,
                created_at=job.created_at,
            )
        )
    return summaries


async def get_job(session: AsyncSession, job_id: int) -> ScanJob | None:
    return await session.get(ScanJob, job_id)


async def cancel_job(session: AsyncSession, job_id: int) -> bool:
    """取消扫描任务。"""
    job = await session.get(ScanJob, job_id)
    if not job:
        return False
    if job.status in ("completed", "failed", "canceled"):
        return False
    # 撤销 Celery 任务
    from ..scan.celery_app import cancel_scan_task

    if job.celery_task_id:
        cancel_scan_task(job.celery_task_id)
    job.status = "canceled"
    job.finished_at = datetime.utcnow()
    await session.commit()
    return True


# ==================== Finding 查询 ====================


async def list_findings(
    session: AsyncSession,
    job_id: int,
    severity: str | None = None,
    tool: str | None = None,
    category: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[Finding], dict[str, int], int]:
    """查询某任务的 finding 列表 + 各严重度计数 + 总数。"""
    # 条件
    conditions = [Finding.job_id == job_id]
    if severity:
        conditions.append(Finding.severity == severity)
    if tool:
        conditions.append(Finding.tool == tool)
    if category:
        conditions.append(Finding.category == category)

    # 总数
    count_stmt = select(func.count()).select_from(Finding).where(*conditions)
    total = (await session.execute(count_stmt)).scalar() or 0

    # 分页查询
    stmt = (
        select(Finding)
        .where(*conditions)
        .order_by(
            # 按严重度排序：critical > high > medium > low > info
            case(
                (Finding.severity == "critical", 5),
                (Finding.severity == "high", 4),
                (Finding.severity == "medium", 3),
                (Finding.severity == "low", 2),
                else_=1,
            ).desc(),
            Finding.created_at.desc(),
        )
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(stmt)
    findings = list(result.scalars().all())

    # 全量严重度计数（不受 severity 过滤影响，供徽章展示）
    count_all_stmt = (
        select(Finding.severity, func.count())
        .where(Finding.job_id == job_id)
        .group_by(Finding.severity)
    )
    count_result = await session.execute(count_all_stmt)
    counts = {row[0]: row[1] for row in count_result.all()}

    return findings, counts, total


# ==================== 门禁策略 ====================


async def list_policies(session: AsyncSession) -> list[ScanPolicy]:
    result = await session.execute(select(ScanPolicy).order_by(ScanPolicy.name))
    return list(result.scalars().all())


async def get_default_policy(session: AsyncSession) -> ScanPolicy | None:
    result = await session.execute(select(ScanPolicy).where(ScanPolicy.is_default == 1).limit(1))
    return result.scalar_one_or_none()


async def upsert_policy(
    session: AsyncSession, data: ScanPolicyCreate, policy_id: int | None = None
) -> ScanPolicy:
    if data.is_default:
        # 取消其他默认
        await session.execute(
            ScanPolicy.__table__.update().where(ScanPolicy.is_default == 1).values(is_default=0)
        )

    if policy_id:
        policy = await session.get(ScanPolicy, policy_id)
        if not policy:
            raise ValueError(f"策略 {policy_id} 不存在")
        policy.name = data.name
        policy.description = data.description
        policy.max_critical = data.max_critical
        policy.max_high = data.max_high
        policy.max_medium = data.max_medium
        policy.max_low = data.max_low
        policy.max_info = data.max_info
        policy.is_default = 1 if data.is_default else 0
    else:
        policy = ScanPolicy(
            name=data.name,
            description=data.description,
            max_critical=data.max_critical,
            max_high=data.max_high,
            max_medium=data.max_medium,
            max_low=data.max_low,
            max_info=data.max_info,
            is_default=1 if data.is_default else 0,
        )
        session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return policy


async def delete_policy(session: AsyncSession, policy_id: int) -> bool:
    policy = await session.get(ScanPolicy, policy_id)
    if not policy:
        return False
    await session.delete(policy)
    await session.commit()
    return True


async def evaluate_gate(
    session: AsyncSession, job_id: int, policy_id: int | None = None
) -> GateResult:
    """评估门禁：按策略阈值判定扫描是否通过。"""
    # 选策略
    if policy_id:
        policy = await session.get(ScanPolicy, policy_id)
    else:
        policy = await get_default_policy(session)
    if not policy:
        # 无策略默认放行
        return GateResult(
            passed=True,
            policy_name="(无策略)",
            counts={},
            reasons=["未配置门禁策略，默认放行"],
        )

    # 统计各严重度
    stmt = (
        select(Finding.severity, func.count())
        .where(Finding.job_id == job_id)
        .group_by(Finding.severity)
    )
    result = await session.execute(stmt)
    counts = {row[0]: row[1] for row in result.all()}

    # 判定
    reasons = []
    checks = [
        ("critical", policy.max_critical, counts.get("critical", 0)),
        ("high", policy.max_high, counts.get("high", 0)),
        ("medium", policy.max_medium, counts.get("medium", 0)),
        ("low", policy.max_low, counts.get("low", 0)),
        ("info", policy.max_info, counts.get("info", 0)),
    ]
    for sev, limit, actual in checks:
        if limit >= 0 and actual > limit:
            reasons.append(f"{sev} 严重度发现 {actual} 条，超过阈值 {limit}")

    return GateResult(
        passed=len(reasons) == 0,
        policy_name=policy.name,
        counts=counts,
        reasons=reasons,
    )


# ==================== CI 上传 ====================


async def upload_scan_results(session: AsyncSession, data: ScanUploadRequest) -> ScanJob:
    """接收 CI 端上传的扫描结果（CI 自己跑了工具，只上传 finding）。"""
    # 找或创建 target
    stmt = select(ScanTarget).where(
        ScanTarget.location == data.location,
        ScanTarget.target_type == data.target_type,
    )
    target = (await session.execute(stmt)).scalar_one_or_none()
    if not target:
        target = ScanTarget(
            name=data.target_name,
            target_type=data.target_type,
            location=data.location,
            ref=data.ref,
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)
        if data.commit:
            target.last_commit = data.commit
            await session.commit()

    # 创建 job（标记为 ci 触发，直接 completed）
    from ..scan.tools.base import FindingRaw

    job = ScanJob(
        target_id=target.id,
        trigger="ci",
        tools=json.dumps(data.tools),
        status="completed",
        progress=100,
        commit=data.commit,
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)

    # 落库 finding（走去重指纹）
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in data.findings:
        raw = FindingRaw(
            tool=f.tool,
            severity=f.severity,
            category=f.category,
            rule_id=f.rule_id,
            cve=f.cve,
            title=f.title,
            message=f.message,
            file=f.file,
            line=f.line,
            fix=f.fix,
        )
        raw.compute_fingerprint()
        finding = Finding(
            job_id=job.id,
            tool=raw.tool,
            severity=raw.severity,
            category=raw.category,
            rule_id=raw.rule_id,
            cve=raw.cve,
            title=raw.title,
            message=raw.message,
            file=raw.file,
            line=raw.line,
            fix=raw.fix,
            fingerprint=raw.fingerprint,
        )
        session.add(finding)
        counts[raw.severity] = counts.get(raw.severity, 0) + 1

    # 回填统计
    job.critical_count = counts["critical"]
    job.high_count = counts["high"]
    job.medium_count = counts["medium"]
    job.low_count = counts["low"]
    job.info_count = counts["info"]
    await session.commit()
    return job


# ==================== 工具列表 ====================


def list_tools() -> list[dict]:
    """列出所有已注册的扫描工具。"""
    from ..scan.tools import list_available_tools

    return list_available_tools()
