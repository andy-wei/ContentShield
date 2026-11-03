"""扫描服务 finding 查询回归测试（内存 DB 集成）。

回归 bug：scan_service.list_findings 曾用 SQLAlchemy 1.x 的 func.case(value=...) 语法，
在 SQLAlchemy 2.0 下报 'Function.__init__() got an unexpected keyword argument value'。
此测试用真实 DB 查询覆盖，确保 case() 语法正确。
"""

from __future__ import annotations

import pytest

from app.models.scan import Finding, ScanJob, ScanTarget


@pytest.fixture
async def db_with_scan_data():
    """构造内存 DB 并插入测试扫描数据。"""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async with sessionmaker() as session:
        # 插入目标 + 任务 + 多严重度 finding
        target = ScanTarget(name="test", target_type="path", location="/tmp")
        session.add(target)
        await session.commit()

        job = ScanJob(
            target_id=target.id,
            tools='["bandit"]',
            status="completed",
        )
        session.add(job)
        await session.commit()

        # 插入不同严重度的 finding（顺序故意打乱，验证排序）
        severities = ["info", "critical", "low", "high", "medium", "critical", "high"]
        for i, sev in enumerate(severities):
            session.add(
                Finding(
                    job_id=job.id,
                    tool="bandit",
                    severity=sev,
                    category="sast",
                    rule_id=f"B{i}",
                    title=f"finding {i}",
                    message=f"msg {i}",
                    file=f"file{i}.py",
                    line=i,
                    fingerprint=f"fp{i}",
                )
            )
        await session.commit()

    yield sessionmaker, job.id

    await engine.dispose()


@pytest.mark.asyncio
async def test_list_findings_orders_by_severity(db_with_scan_data):
    """finding 应按严重度降序排列：critical > high > medium > low > info。"""
    sessionmaker, job_id = db_with_scan_data
    from app.services.scan_service import list_findings

    async with sessionmaker() as session:
        findings, counts, total = await list_findings(session, job_id)

    assert total == 7
    # 验证排序：前两条应是 critical
    assert findings[0].severity == "critical"
    assert findings[1].severity == "critical"
    # 接着是 high
    assert findings[2].severity == "high"
    assert findings[3].severity == "high"
    # 然后 medium
    assert findings[4].severity == "medium"
    # low
    assert findings[5].severity == "low"
    # 最后 info
    assert findings[6].severity == "info"


@pytest.mark.asyncio
async def test_list_findings_severity_counts(db_with_scan_data):
    """counts 应正确统计各严重度。"""
    sessionmaker, job_id = db_with_scan_data
    from app.services.scan_service import list_findings

    async with sessionmaker() as session:
        findings, counts, total = await list_findings(session, job_id)

    assert counts.get("critical") == 2
    assert counts.get("high") == 2
    assert counts.get("medium") == 1
    assert counts.get("low") == 1
    assert counts.get("info") == 1


@pytest.mark.asyncio
async def test_list_findings_filter_by_severity(db_with_scan_data):
    """按 severity 过滤应只返回对应严重度。"""
    sessionmaker, job_id = db_with_scan_data
    from app.services.scan_service import list_findings

    async with sessionmaker() as session:
        findings, counts, total = await list_findings(session, job_id, severity="critical")

    assert total == 2
    assert all(f.severity == "critical" for f in findings)
