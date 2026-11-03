"""Celery 任务定义。

任务注册到 celery_app，由 worker 进程消费。
"""

from __future__ import annotations

import asyncio
import logging

from .celery_app import celery_app
from .runner import run_scan_job

logger = logging.getLogger(__name__)


@celery_app.task(name="scan.run", bind=True)
def run_scan_task(self, job_id: int) -> dict:
    """执行 DevSecOps 扫描任务。

    self.request.id 是 Celery 分配的任务 ID，FastAPI 层派发后会把
    celery_task_id 写回 ScanJob（用于查询状态/取消）。
    """
    logger.info("Celery 任务 %s: 开始扫描 job_id=%s", self.request.id, job_id)
    try:
        run_scan_job(job_id)
        return {"job_id": job_id, "status": "completed"}
    except Exception as e:  # noqa: BLE001
        # runner 内部已处理状态标记，这里只记录并返回
        logger.exception("扫描任务 %s 异常", job_id)
        return {"job_id": job_id, "status": "failed", "error": str(e)}


@celery_app.task(name="training.scan")
def run_training_scan_task(scan_id: int) -> dict:
    """执行训练数据集扫描任务。

    training_service.execute_scan 是 async 函数，需在 Celery worker 里跑事件循环。
    """
    logger.info("Celery 任务: 开始训练数据扫描 scan_id=%s", scan_id)
    from ..services.training_service import execute_scan

    try:
        asyncio.run(execute_scan(scan_id))
        return {"scan_id": scan_id, "status": "completed"}
    except Exception as e:  # noqa: BLE001
        logger.exception("训练数据扫描 %s 异常", scan_id)
        return {"scan_id": scan_id, "status": "failed", "error": str(e)}


@celery_app.task(name="redteam.run")
def run_redteam_task(campaign_id: int) -> dict:
    """执行红队对抗测试任务。

    runner.run_campaign 是 async 函数，需在 Celery worker 里跑事件循环。
    """
    logger.info("Celery 任务: 开始红队对抗测试 campaign_id=%s", campaign_id)
    from ..redteam.runner import run_campaign

    try:
        asyncio.run(run_campaign(campaign_id))
        return {"campaign_id": campaign_id, "status": "completed"}
    except Exception as e:  # noqa: BLE001
        logger.exception("红队测试 %s 异常", campaign_id)
        return {"campaign_id": campaign_id, "status": "failed", "error": str(e)}


@celery_app.task(name="redteam.membership")
def run_membership_inference_task(campaign_id: int) -> dict:
    """执行成员推理攻击任务。

    与普通红队不同：不发攻击 prompt，而是发探针集统计响应特征差异。
    """
    logger.info("Celery 任务: 开始成员推理攻击 campaign_id=%s", campaign_id)
    from ..services.redteam_service import execute_mia

    try:
        asyncio.run(execute_mia(campaign_id))
        return {"campaign_id": campaign_id, "status": "completed"}
    except Exception as e:  # noqa: BLE001
        logger.exception("成员推理攻击 %s 异常", campaign_id)
        return {"campaign_id": campaign_id, "status": "failed", "error": str(e)}
