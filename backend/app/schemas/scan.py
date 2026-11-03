"""DevSecOps 扫描平台的 Pydantic 请求/响应模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# ==================== 枚举 ====================

Severity = Literal["critical", "high", "medium", "low", "info"]
FindingCategory = Literal["sast", "sca", "secret", "container", "config", "license"]
TargetType = Literal["git", "path", "image"]
JobStatus = Literal["pending", "running", "completed", "failed", "canceled"]
Trigger = Literal["manual", "ci", "schedule"]


# ==================== 扫描目标 ====================


class ScanTargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    target_type: TargetType = "git"
    location: str = Field(..., min_length=1, max_length=512)
    ref: str = Field("main", max_length=128)


class ScanTargetOut(BaseModel):
    id: int
    name: str
    target_type: TargetType
    location: str
    ref: str
    last_commit: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ==================== 扫描任务 ====================


class ScanJobCreate(BaseModel):
    target_id: int
    tools: list[str] = Field(default_factory=lambda: ["bandit", "gitleaks", "pip_audit"])
    trigger: Trigger = "manual"


class ScanJobOut(BaseModel):
    id: int
    target_id: int
    trigger: Trigger
    tools: list[str]
    status: JobStatus
    celery_task_id: str
    commit: str
    progress: int
    error: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    # 冗余统计
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_tools(cls, job) -> ScanJobOut:
        """从 ORM 构造，自动解析 tools JSON 字符串。"""
        import json

        data = {c.name: getattr(job, c.name) for c in job.__table__.columns}
        try:
            data["tools"] = json.loads(data.get("tools") or "[]")
        except (json.JSONDecodeError, TypeError):
            data["tools"] = []
        return cls.model_validate(data)


class ScanJobSummary(BaseModel):
    """任务列表项（精简，含 target 名称）。"""

    id: int
    target_id: int
    target_name: str
    trigger: Trigger
    tools: list[str]
    status: JobStatus
    progress: int
    commit: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


# ==================== Finding ====================


class FindingOut(BaseModel):
    id: int
    job_id: int
    tool: str
    severity: Severity
    category: FindingCategory
    rule_id: str
    cve: str
    title: str
    message: str
    file: str
    line: int
    fix: str
    fingerprint: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingList(BaseModel):
    """分页 finding 查询结果。"""

    items: list[FindingOut]
    total: int
    # 按 severity 的统计（方便前端展示徽章）
    counts: dict[str, int]


# ==================== 门禁策略 ====================


class ScanPolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: str = ""
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = -1
    max_low: int = -1
    max_info: int = -1
    is_default: bool = False


class ScanPolicyOut(BaseModel):
    id: int
    name: str
    description: str
    max_critical: int
    max_high: int
    max_medium: int
    max_low: int
    max_info: int
    is_default: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class GateResult(BaseModel):
    """门禁判定结果（给 CI 用）。"""

    passed: bool
    policy_name: str
    counts: dict[str, int]
    # 触发失败的具体原因
    reasons: list[str]


# ==================== 可用工具 ====================


class ToolInfo(BaseModel):
    """扫描工具元信息。"""

    name: str
    category: FindingCategory
    description: str
    # 工具是否可用（二进制是否存在）
    available: bool


# ==================== 上传（CI 接收结果） ====================


class FindingUpload(BaseModel):
    """CI 端跑完扫描后上传单条 finding。"""

    tool: str
    severity: Severity
    category: FindingCategory
    rule_id: str = ""
    cve: str = ""
    title: str = ""
    message: str = ""
    file: str = ""
    line: int = 0
    fix: str = ""


class ScanUploadRequest(BaseModel):
    """CI 上传扫描结果的批量请求。"""

    target_name: str
    target_type: TargetType = "git"
    location: str
    ref: str = "main"
    commit: str = ""
    tools: list[str] = Field(default_factory=list)
    findings: list[FindingUpload] = Field(default_factory=list)
