"""审计 checklist 的 Pydantic 模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

ChecklistStatus = Literal["pending", "pass", "fail", "na"]
CheckMethod = Literal["code_review", "config_check", "tool_scan", "pentest"]


class AuditChecklistItemOut(BaseModel):
    id: int
    owasp_id: str
    name: str
    threat_category: str
    audit_points: list[str]
    check_method: CheckMethod
    ref_layer: str
    status: ChecklistStatus
    evidence: str
    auditor: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_json(cls, item) -> AuditChecklistItemOut:
        """从 ORM 构造，解析 audit_points JSON。"""
        import json

        data = {c.name: getattr(item, c.name) for c in item.__table__.columns}
        try:
            data["audit_points"] = json.loads(data.get("audit_points") or "[]")
        except (json.JSONDecodeError, TypeError):
            data["audit_points"] = []
        return cls.model_validate(data)


class ChecklistUpdateRequest(BaseModel):
    """更新 checklist 项状态。"""

    status: ChecklistStatus
    evidence: str = ""
    auditor: str = ""


class ChecklistSummary(BaseModel):
    """审计进度摘要。"""

    total: int
    pass_count: int
    fail_count: int
    pending_count: int
    na_count: int
    pass_rate: float
