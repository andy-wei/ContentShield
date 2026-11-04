"""审计日志模型：记录每一次检测请求与各层结果。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )

    # 请求来源标识（user_prompt / llm_response / gateway 等）
    source: Mapped[str] = mapped_column(String(64), index=True)
    # 输入文本（若 AUDIT_REDACT_PII=true，命中 PII 片段会被打码）
    input_text: Mapped[str] = mapped_column(Text)
    # 文本长度
    input_length: Mapped[int] = mapped_column(Integer, default=0)
    # 最终决策：block / warn / pass
    decision: Mapped[str] = mapped_column(String(16), index=True)
    # 综合风险评分 0-1
    risk_score: Mapped[float] = mapped_column(default=0.0)
    # 命中的类别代码（如 ["S2", "S-injection"]）
    categories: Mapped[list] = mapped_column(JSON, default=list)
    # 各层结果（结构化）
    layers: Mapped[dict] = mapped_column(JSON, default=dict)
    # 可解释说明列表
    explanations: Mapped[list] = mapped_column(JSON, default=list)
    # 总耗时 ms
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    # 网关模式下的上游响应（可选）
    gateway_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 身份归因（NHI 动态凭据管理）：记录是谁发起的检测
    principal_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(128), default="", index=True)
    scopes: Mapped[str] = mapped_column(String(256), default="")
