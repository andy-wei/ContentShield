"""训练数据安全扫描数据模型：数据集、扫描任务、问题样本。

设计要点：
- 复用运行时 6 层检测引擎（orchestrator.moderate）扫描每条样本
- 额外的训练投毒检测（poison_patterns）：重复指令注入/角色覆盖/隐蔽触发词
- DatasetFinding 记录单条问题样本，含命中层 + 投毒嫌疑类型
- 样本溯源：record_hash 用于跨次扫描去重与版本追踪
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Dataset(Base):
    """训练/微调数据集。"""

    __tablename__ = "training_datasets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    # jsonl / csv / txt
    format: Mapped[str] = mapped_column(String(16), default="jsonl", index=True)
    # 数据来源（huggingface / 内部 / 爬取 / 用户上传）
    source: Mapped[str] = mapped_column(String(64), default="internal")
    # 版本标签（如 v1.0 / 2026-07-01）
    version: Mapped[str] = mapped_column(String(32), default="")
    # 样本总数（扫描时回填）
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    # 原始文件路径（上传后存储的路径，相对 data_dir）
    file_path: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class DatasetScan(Base):
    """一次数据集安全扫描。"""

    __tablename__ = "training_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("training_datasets.id", ondelete="CASCADE"), index=True
    )
    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # 扫描了多少条样本
    scanned_count: Mapped[int] = mapped_column(Integer, default=0)
    # 命中问题样本数
    flagged_count: Mapped[int] = mapped_column(Integer, default=0)
    # 各类问题统计 JSON：{"pii": 5, "toxic": 3, "injection": 2, "poison": 1}
    stats: Mapped[str] = mapped_column(Text, default="{}")
    # 进度百分比 0-100
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class DatasetFinding(Base):
    """单条问题样本。"""

    __tablename__ = "training_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("training_scans.id", ondelete="CASCADE"), index=True
    )
    # 样本在数据集中的行号（0-based）
    record_idx: Mapped[int] = mapped_column(Integer, index=True)
    # 样本内容哈希（SHA256 前 16 字符），用于去重和溯源
    record_hash: Mapped[str] = mapped_column(String(32), default="", index=True)
    # 问题类型 JSON 数组：["pii","toxic","injection","poison"]
    issue_types: Mapped[str] = mapped_column(Text, default="[]")
    # 该样本的检测决策（block/warn/modify）
    decision: Mapped[str] = mapped_column(String(16), default="pass")
    # 风险评分 0-1
    risk_score: Mapped[float] = mapped_column(default=0.0)
    # 命中的层 JSON：{"dlp":{"hit":true},"llama_guard":{"hit":true}}
    layers: Mapped[str] = mapped_column(Text, default="{}")
    # 命中类别 JSON 数组（如 ["pii:中国手机号", "S3"]）
    categories: Mapped[str] = mapped_column(Text, default="[]")
    # 投毒嫌疑类型（如有）：如 "instruction_injection" / "role_override" / "hidden_trigger"
    poison_type: Mapped[str] = mapped_column(String(32), default="", index=True)
    # 样本预览（前 200 字符，PII 已脱敏）
    preview: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
