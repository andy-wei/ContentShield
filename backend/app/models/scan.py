"""DevSecOps 扫描平台数据模型：扫描目标、扫描任务、漏洞发现、门禁策略。

设计要点：
- Finding 标准化：多工具结果统一为 (severity, category, fingerprint) 三元组，
  支持跨工具去重与跨次扫描对比。
- fingerprint = hash(tool + file + line + rule_id)：同一漏洞多次扫描可识别。
- ScanPolicy：CI 门禁策略，按 severity 阈值判定 pass/fail。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ScanTarget(Base):
    """扫描目标（git 仓库 / 本地路径 / 容器镜像）。"""

    __tablename__ = "scan_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    # git / path / image
    target_type: Mapped[str] = mapped_column(String(16), default="git", index=True)
    # git 时为仓库 URL；path 时为绝对路径；image 时为镜像 tag
    location: Mapped[str] = mapped_column(String(512))
    # git 时的分支/commit，path/image 可空
    ref: Mapped[str] = mapped_column(String(128), default="main")
    # 上次扫描拉取到的 commit sha（git 类型，用于增量对比）
    last_commit: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class ScanJob(Base):
    """一次扫描任务。"""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_targets.id", ondelete="CASCADE"), index=True
    )
    # 触发来源：manual / ci / schedule
    trigger: Mapped[str] = mapped_column(String(16), default="manual")
    # 本次扫描使用的工具列表 JSON 数组字符串，如 ["bandit","gitleaks"]
    tools: Mapped[str] = mapped_column(Text, default="[]")
    # pending / running / completed / failed / canceled
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # Celery 任务 ID（用于查询/取消）
    celery_task_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    # 扫描的工作目录（拉取的代码/挂载的路径）
    workdir: Mapped[str] = mapped_column(String(512), default="")
    # 本次扫描到的 commit（git）
    commit: Mapped[str] = mapped_column(String(64), default="")
    # 进度百分比 0-100
    progress: Mapped[int] = mapped_column(Integer, default=0)
    # 失败时的错误信息
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )

    # 关联的统计（冗余字段，加速列表查询，scan 完成时回填）
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Base):
    """一条标准化的漏洞发现。"""

    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    # 发现该漏洞的工具：bandit / semgrep / gitleaks / trivy / pip_audit / npm_audit / syft
    tool: Mapped[str] = mapped_column(String(32), index=True)
    # critical / high / medium / low / info
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    # sast / sca / secret / container / config / license
    category: Mapped[str] = mapped_column(String(16), default="sast", index=True)
    # 工具原始规则 ID（如 bandit 的 B602、semgrep 的 rule id、trivy 的 CVE）
    rule_id: Mapped[str] = mapped_column(String(128), default="")
    # CVE 编号（SCA/container 类别常有）
    cve: Mapped[str] = mapped_column(String(32), default="", index=True)
    # 漏洞标题/描述
    title: Mapped[str] = mapped_column(String(512), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    # 文件路径（相对仓库根）
    file: Mapped[str] = mapped_column(String(512), default="", index=True)
    line: Mapped[int] = mapped_column(Integer, default=0)
    # 修复建议
    fix: Mapped[str] = mapped_column(Text, default="")
    # 去重指纹 hash(tool + file + line + rule_id)，用于跨次对比
    fingerprint: Mapped[str] = mapped_column(String(64), default="", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class ScanPolicy(Base):
    """CI 门禁策略：按 severity 阈值判定扫描是否通过。"""

    __tablename__ = "scan_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    # 各 severity 的最大允许数量，超过即门禁失败；-1 表示不限制
    max_critical: Mapped[int] = mapped_column(Integer, default=0)
    max_high: Mapped[int] = mapped_column(Integer, default=0)
    max_medium: Mapped[int] = mapped_column(Integer, default=-1)
    max_low: Mapped[int] = mapped_column(Integer, default=-1)
    max_info: Mapped[int] = mapped_column(Integer, default=-1)
    is_default: Mapped[bool] = mapped_column(Integer, default=0)  # SQLite 用 0/1 存布尔
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
