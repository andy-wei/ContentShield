"""系统配置模型（key-value 动态配置，支持运行时修改无需重启）。

用于存储可在 UI 配置的运行时参数（如交叉验证模型配置）。
敏感值（如 API Key）用 Fernet 加密存储。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class SystemConfig(Base):
    """系统配置表（key-value）。

    key: 配置键（如 "cross_verify.enabled"）
    value: 配置值（明文，非敏感）
    value_enc: 敏感配置的加密值（如 API Key）
    is_secret: 标记是否为敏感字段（True 时用 value_enc，读出需解密）
    """

    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[str] = mapped_column(Text, default="")
    value_enc: Mapped[str] = mapped_column(Text, default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(String(256), default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
