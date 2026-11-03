"""扫描执行器：编排「拉取目标 → 跑工具 → 去重 → 落库」。

这是 Celery 任务调用的核心，本身是同步函数（在 worker 进程中跑）。
通过同步 SQLAlchemy session 操作 DB（Celery worker 默认无事件循环）。
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from ..config import settings
from ..models.scan import Finding, ScanJob, ScanTarget
from .dedup import dedup_findings
from .tools import get_adapter

logger = logging.getLogger(__name__)

# 严重度 → 统计字段
_SEV_FIELD = {
    "critical": "critical_count",
    "high": "high_count",
    "medium": "medium_count",
    "low": "low_count",
    "info": "info_count",
}


def run_scan_job(job_id: int) -> None:
    """执行一次扫描任务（由 Celery 调用）。

    步骤：
    1. 从 DB 读 job + target
    2. 标记 job 为 running
    3. 准备工作目录（git clone / 直接用 path / image）
    4. 依次跑各工具，收集 FindingRaw
    5. 跨工具去重
    6. 落库 finding + 回填 job 统计
    """
    # Celery worker 用同步 engine
    sync_url = _to_sync_url(settings.database_url)
    engine = create_engine(sync_url)

    try:
        with Session(engine) as session:
            job = session.get(ScanJob, job_id)
            if not job:
                logger.error("扫描任务 %s 不存在", job_id)
                return
            target = session.get(ScanTarget, job.target_id)
            if not target:
                _fail_job(session, job, "扫描目标不存在")
                return

            import json

            tools = json.loads(job.tools or "[]")
            _mark_running(session, job)

            # 准备工作目录
            workdir, commit = _prepare_workdir(target)
            job.workdir = workdir
            if commit:
                job.commit = commit
                # 更新 target 的 last_commit
                target.last_commit = commit
            session.commit()

            # 依次跑工具
            all_findings = []
            total_tools = len(tools)
            for idx, tool_name in enumerate(tools):
                adapter = get_adapter(tool_name)
                if not adapter:
                    logger.warning("未知工具 %s，跳过", tool_name)
                    continue
                if not adapter.is_available():
                    logger.warning("工具 %s 不可用，跳过", tool_name)
                    continue
                try:
                    logger.info("任务 %s: 运行 %s ...", job_id, tool_name)
                    if tool_name == "trivy" and target.target_type == "image":
                        raw = adapter.run(workdir, image=target.location)
                    else:
                        raw = adapter.run(workdir)
                    all_findings.extend(raw)
                except subprocess.TimeoutExpired:
                    logger.error("工具 %s 超时", tool_name)
                except Exception:  # noqa: BLE001
                    logger.exception("工具 %s 执行异常", tool_name)

                # 更新进度
                job.progress = int((idx + 1) / total_tools * 80)
                session.commit()

            # 去重
            deduped = dedup_findings(all_findings)
            logger.info(
                "任务 %s: 原始 %d 条 → 去重后 %d 条", job_id, len(all_findings), len(deduped)
            )

            # 落库 finding
            for raw in deduped:
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

            # 回填统计
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for raw in deduped:
                counts[raw.severity] = counts.get(raw.severity, 0) + 1
            for sev, field in _SEV_FIELD.items():
                setattr(job, field, counts.get(sev, 0))

            # 标记完成
            job.status = "completed"
            job.progress = 100
            job.finished_at = datetime.utcnow()
            session.commit()
            logger.info("任务 %s 完成: %s", job_id, counts)

    finally:
        engine.dispose()


# ==================== 工作目录准备 ====================


def _prepare_workdir(target: ScanTarget) -> tuple[str, str]:
    """根据 target_type 准备扫描工作目录。

    返回 (workdir, commit)：
    - git: 临时目录 clone，返回 commit sha
    - path: 直接用 location，commit 为空
    - image: 返回空 workdir（trivy 直接扫 image）
    """
    if target.target_type == "image":
        return "", ""

    if target.target_type == "path":
        return target.location, ""

    # git: clone 到临时目录
    workdir = tempfile.mkdtemp(prefix="cs_scan_")
    ref = target.ref or "main"
    try:
        # 浅克隆加速
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, target.location, workdir],
            capture_output=True,
            timeout=120,
            check=True,
        )
        # 获取 commit sha
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        commit = result.stdout.strip()
        return workdir, commit
    except subprocess.CalledProcessError as e:
        shutil.rmtree(workdir, ignore_errors=True)
        raise RuntimeError(f"git clone 失败: {e.stderr.decode(errors='replace')}") from e
    except subprocess.TimeoutExpired as e:
        shutil.rmtree(workdir, ignore_errors=True)
        raise RuntimeError("git clone 超时") from e


# ==================== DB 辅助 ====================


def _mark_running(session: Session, job: ScanJob) -> None:
    job.status = "running"
    job.progress = 0
    job.started_at = datetime.utcnow()
    session.commit()


def _fail_job(session: Session, job: ScanJob, error: str) -> None:
    job.status = "failed"
    job.error = error
    job.finished_at = datetime.utcnow()
    session.commit()


def _to_sync_url(async_url: str) -> str:
    """把 async driver URL 转为同步 driver URL。"""
    # sqlite+aiosqlite:// → sqlite://
    url = async_url.replace("+aiosqlite", "")
    # postgresql+asyncpg:// → postgresql://
    url = url.replace("+asyncpg", "")
    return url


def cleanup_workdir(workdir: str) -> None:
    """清理临时工作目录。"""
    if workdir and workdir.startswith(tempfile.gettempdir()) and os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)
