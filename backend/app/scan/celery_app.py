"""Celery 应用与任务定义。

Celery worker 启动：celery -A app.scan.celery_app worker --loglevel=info

设计：
- Celery 任务是同步函数，内部调 runner.run_scan_job（用同步 SQLAlchemy session）。
- FastAPI 主进程通过 run_scan_task.delay(job_id) 派发任务，拿到 celery_task_id 写回 DB。
- runner 内部已处理状态流转（pending→running→completed/failed），Celery 层只兜底未知异常。
"""

from __future__ import annotations

import logging

from celery import Celery

from ..config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "contentshield",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.scan.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=settings.tz,
    enable_utc=True,
    task_time_limit=settings.scan_task_timeout,
    task_soft_time_limit=max(settings.scan_task_timeout - 60, 60),
    result_expires=7 * 24 * 3600,
    # 扫描任务重，一次只预取一个
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
    # 扫描失败不自动重试（避免重复跑 trivy 等慢工具）
    task_autoretry_for=(),
)


def cancel_scan_task(celery_task_id: str) -> bool:
    """撤销扫描任务。返回是否发出了撤销指令。"""
    if not celery_task_id:
        return False
    celery_app.control.revoke(celery_task_id, terminate=True)
    return True
