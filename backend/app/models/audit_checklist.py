"""OWASP LLM Top 10 审计 checklist 数据模型。

把 OWASP LLM Top 10（2025）的 10 类风险固化为可逐项审计的 checklist，
每项含审计要点、对应的威胁类别、检查方法、状态跟踪。

设计要点：
- 独立于 threat_model（checklist 是审计工具，不是威胁实例）
- 映射到 STRIDE + AI 维度的类别，可与威胁建模交叉引用
- 状态流转：pending → pass / fail / na，记录审计证据
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class AuditChecklistItem(Base):
    """一项审计 checklist（对应 OWASP LLM Top 10 的一类风险）。"""

    __tablename__ = "audit_checklist_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # OWASP 编号：LLM01 ~ LLM10
    owasp_id: Mapped[str] = mapped_column(String(8), unique=True, index=True)
    # 风险名称（如 "Prompt Injection"）
    name: Mapped[str] = mapped_column(String(128))
    # 对应的威胁类别（STRIDE + AI 维度），便于与威胁建模交叉
    threat_category: Mapped[str] = mapped_column(String(32), default="", index=True)
    # 审计要点（JSON 数组字符串）：具体要检查什么
    audit_points: Mapped[str] = mapped_column(Text, default="[]")
    # 检查方法（代码审计/配置检查/渗透测试/工具扫描）
    check_method: Mapped[str] = mapped_column(String(32), default="code_review")
    # 对应的检测层（与 threat_model.ref_layer 对齐）
    ref_layer: Mapped[str] = mapped_column(String(32), default="manual")
    # 状态：pending / pass / fail / na
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # 审计证据/备注
    evidence: Mapped[str] = mapped_column(Text, default="")
    # 审计人
    auditor: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
