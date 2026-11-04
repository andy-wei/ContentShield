"""策略规则模型：类别开关、词库、DLP 正则、网关 API Key。"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class CategoryRule(Base):
    """Llama-Guard-4 的 S1–S14 类别配置（可启用/禁用 + 自定义描述）。"""

    __tablename__ = "category_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # 类别代码，如 "S2"（主键约束在业务层）
    code: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    # 展示名称
    name: Mapped[str] = mapped_column(String(128))
    # 是否启用
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # 处置：block / warn / off
    action: Mapped[str] = mapped_column(String(16), default="block")
    # 自定义描述（覆盖官方默认，用于提示词构造）
    description: Mapped[str] = mapped_column(Text, default="")
    # 层级（用于统计分组）
    layer: Mapped[str] = mapped_column(String(32), default="llama_guard")
    # 排序
    order: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class LexiconEntry(Base):
    """词库条目（L0 脏话/辱骂/色情关键词）。"""

    __tablename__ = "lexicon_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    term: Mapped[str] = mapped_column(String(128), index=True)
    # 分类：profanity / abuse / sexual / violence ...
    category: Mapped[str] = mapped_column(String(32), index=True, default="profanity")
    # 语言：zh / en
    lang: Mapped[str] = mapped_column(String(8), default="zh")
    # 处置：block / warn
    action: Mapped[str] = mapped_column(String(16), default="block")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class DlpRule(Base):
    """DLP 正则规则（L3 密钥/凭证/PII）。"""

    __tablename__ = "dlp_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), index=True)
    # 正则表达式
    pattern: Mapped[str] = mapped_column(Text)
    # 分类：secret / pii / credential ...
    category: Mapped[str] = mapped_column(String(32), index=True, default="secret")
    # 命中后处置
    action: Mapped[str] = mapped_column(String(16), default="block")
    # 严重度权重（贡献到风险评分）
    weight: Mapped[float] = mapped_column(Float, default=0.5)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class ApiKey(Base):
    """网关访问凭证（客户端调用 /v1/moderate / /v1/chat/completions 用）。"""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # 仅存 SHA256 哈希，原文不入库
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
