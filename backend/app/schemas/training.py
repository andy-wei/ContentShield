"""训练数据安全扫描的 Pydantic 请求/响应模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

DatasetFormat = Literal["jsonl", "csv", "txt"]
ScanStatus = Literal["pending", "running", "completed", "failed"]
IssueType = Literal["pii", "toxic", "injection", "poison", "secret", "other"]
PoisonType = Literal[
    "",
    "instruction_injection",
    "role_override",
    "hidden_trigger",
    "repeated_pattern",
    "format_anomaly",
]


# ==================== 数据集 ====================


class DatasetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = ""
    format: DatasetFormat = "jsonl"
    source: str = "internal"
    version: str = ""


class DatasetOut(BaseModel):
    id: int
    name: str
    description: str
    format: DatasetFormat
    source: str
    version: str
    record_count: int
    file_path: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==================== 扫描任务 ====================


class DatasetScanOut(BaseModel):
    id: int
    dataset_id: int
    status: ScanStatus
    scanned_count: int
    flagged_count: int
    stats: dict
    progress: int
    error: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_stats(cls, scan) -> DatasetScanOut:
        """从 ORM 构造，自动解析 stats JSON。"""
        import json

        data = {c.name: getattr(scan, c.name) for c in scan.__table__.columns}
        try:
            data["stats"] = json.loads(data.get("stats") or "{}")
        except (json.JSONDecodeError, TypeError):
            data["stats"] = {}
        return cls.model_validate(data)


class DatasetScanSummary(BaseModel):
    """扫描列表项（含数据集名称）。"""

    id: int
    dataset_id: int
    dataset_name: str
    status: ScanStatus
    scanned_count: int
    flagged_count: int
    stats: dict
    progress: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


# ==================== 问题样本 ====================


class DatasetFindingOut(BaseModel):
    id: int
    scan_id: int
    record_idx: int
    record_hash: str
    issue_types: list[str]
    decision: str
    risk_score: float
    layers: dict
    categories: list[str]
    poison_type: str
    preview: str
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_json(cls, finding) -> DatasetFindingOut:
        """从 ORM 构造，解析 JSON 字段。"""
        import json

        data = {c.name: getattr(finding, c.name) for c in finding.__table__.columns}
        for field in ("issue_types", "categories"):
            try:
                data[field] = json.loads(data.get(field) or "[]")
            except (json.JSONDecodeError, TypeError):
                data[field] = []
        try:
            data["layers"] = json.loads(data.get("layers") or "{}")
        except (json.JSONDecodeError, TypeError):
            data["layers"] = {}
        return cls.model_validate(data)


class DatasetFindingList(BaseModel):
    """分页问题样本查询结果。"""

    items: list[DatasetFindingOut]
    total: int
    # 按问题类型统计
    issue_counts: dict[str, int]


# ==================== 扫描报告 ====================


class DatasetScanReport(BaseModel):
    """扫描完成后的汇总报告。"""

    scan: DatasetScanOut
    dataset: DatasetOut
    # 问题样本分布
    issue_distribution: dict[str, int]
    # 投毒嫌疑样本数
    poison_suspect_count: int
    # 风险评分分布（按区间）
    risk_distribution: dict[str, int]
    # 最严重的 Top 5 样本
    top_findings: list[DatasetFindingOut]
