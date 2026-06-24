"""身份与凭据管理的 Pydantic 模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---- OAuth 2.0 端点 ----

class TokenRequest(BaseModel):
    """OAuth 2.0 Client Credentials Grant 请求。"""

    grant_type: Literal["client_credentials", "refresh_token"]
    client_id: str | None = None
    client_secret: str | None = None
    refresh_token: str | None = None
    scope: str | None = None


class TokenResponse(BaseModel):
    """OAuth 2.0 标准 token 响应。"""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str
    refresh_token: str | None = None


class RevokeRequest(BaseModel):
    """Token 撤销请求 (RFC 7009)。"""

    token: str
    token_type_hint: Literal["access_token", "refresh_token"] | None = None


class IntrospectRequest(BaseModel):
    """Token 内省请求 (RFC 7662)。"""

    token: str


class IntrospectResponse(BaseModel):
    """Token 内省响应。"""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    sub: str | None = None
    exp: int | None = None
    token_type: str = "Bearer"


# ---- NHI 管理 ----

class NhiPrincipalCreate(BaseModel):
    """创建 NHI 请求。"""

    label: str = Field(..., description="展示名称")
    principal_type: Literal["agent", "service", "mcp_server"] = "agent"
    scopes: str = "moderate:read,moderate:write,gateway:proxy"
    # 可选：绑定专属上游凭据（为空则用全局配置）
    upstream_provider: str | None = None
    upstream_api_key: str | None = None
    upstream_base_url: str | None = None


class NhiPrincipalCreated(BaseModel):
    """创建 NHI 响应（含一次性明文 secret）。"""

    id: int
    client_id: str
    client_secret: str = Field(..., description="明文 secret，仅此一次返回，请妥善保存")
    label: str
    principal_type: str
    scopes: str
    created_at: datetime

    model_config = {"from_attributes": True}


class NhiPrincipalRead(BaseModel):
    """NHI 列表/详情（不含 secret）。"""

    id: int
    client_id: str
    label: str
    principal_type: str
    enabled: bool
    scopes: str
    upstream_provider: str
    upstream_base_url: str
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None = None

    model_config = {"from_attributes": True}


class SecretRotated(BaseModel):
    """轮转 secret 响应（含新明文 secret）。"""

    id: int
    client_id: str
    client_secret: str = Field(..., description="新的明文 secret，仅此一次")


class AccessTokenRead(BaseModel):
    """活跃 token 列表项。"""

    id: int
    jti: str
    principal_id: int
    subject: str
    scopes: str
    expires_at: datetime
    revoked: bool
    created_at: datetime

    model_config = {"from_attributes": True}
