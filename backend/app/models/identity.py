"""身份与凭据管理数据模型。

NhiPrincipal: 非人类身份（Agent/服务的机器身份）
AccessToken:  已颁发的 JWT（用于黑名单撤销 + 审计）
RefreshToken: refresh token（续签 access token）
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class NhiPrincipal(Base):
    """非人类身份（Agent/服务的机器身份）。

    每个 Agent 获得独立的 client_id + client_secret（Fernet 加密存储），
    可绑定各自的上游凭据（替代全局 settings.gateway_upstream_api_key）。
    """

    __tablename__ = "nhi_principals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # 如 "agent-customer-support-01"，客户端用它请求 token
    client_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    # client_secret 的 Fernet 密文（明文仅创建/轮转时返回一次）
    client_secret_enc: Mapped[str] = mapped_column(Text, default="")
    label: Mapped[str] = mapped_column(String(128), default="")
    # "agent" / "service" / "mcp_server"
    principal_type: Mapped[str] = mapped_column(String(32), default="agent")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # 权限范围，逗号分隔
    scopes: Mapped[str] = mapped_column(
        String(256), default="moderate:read,moderate:write,gateway:proxy"
    )
    # 该身份绑定的上游凭据（加密），为空则回退全局配置
    upstream_provider: Mapped[str] = mapped_column(String(32), default="")
    upstream_api_key_enc: Mapped[str] = mapped_column(Text, default="")
    upstream_base_url: Mapped[str] = mapped_column(String(256), default="")
    # 工具白名单（JSON 数组，空列表=全部允许）
    # 如 ["web_search","calculator","get_weather"]
    allowed_tools: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AccessToken(Base):
    """已颁发的 JWT access token（黑名单撤销 + 审计）。"""

    __tablename__ = "access_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jti: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    principal_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("nhi_principals.id"), index=True
    )
    subject: Mapped[str] = mapped_column(String(128))
    scopes: Mapped[str] = mapped_column(String(256), default="")
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RefreshToken(Base):
    """refresh token（续签 access token）。原文不入库，仅存哈希。"""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    principal_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("nhi_principals.id"), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
