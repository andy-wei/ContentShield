"""Agent 工具调用动作审计模型。

记录 Agent 的每个 tool_call（工具名、参数摘要、来源身份、是否被拦截），
用于执行链追踪和安全审计。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class AgentAction(Base):
    """Agent 工具调用动作审计记录。"""

    __tablename__ = "agent_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    # 调用者身份
    principal_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(128), default="anonymous", index=True)
    # 工具调用信息
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    arguments_summary: Mapped[str] = mapped_column(
        Text, default=""
    )  # 参数摘要（脱敏后，前 200 字符）
    # 来源：request（请求中声明）/ response（LLM 响应中调用）
    source: Mapped[str] = mapped_column(String(32), default="request")
    # 拦截状态
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    block_reason: Mapped[str] = mapped_column(String(256), default="")
    # 关联同一次请求的多个动作
    request_id: Mapped[str] = mapped_column(String(64), default="", index=True)
