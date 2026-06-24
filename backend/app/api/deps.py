"""统一鉴权依赖：JWT 解析 → NHI 查库 → 返回 Identity（含动态上游凭据）。

设计要点：
- get_identity 注入到所有需鉴权路由（/v1/moderate, /v1/chat/completions, /v1/tools/*）
- 开发模式（未配置 ENCRYPTION_KEY）：降级为 anonymous，不鉴权，用全局上游凭据
- 生产模式：解析 Bearer JWT → 校验签名/过期/黑名单 → 查 NhiPrincipal → 解密上游凭据
"""
from __future__ import annotations

import logging

import jwt
from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models.identity import NhiPrincipal
from ..security import jwt_service
from ..security.blacklist import is_revoked
from ..security.crypto import decrypt, is_encryption_enabled

logger = logging.getLogger(__name__)


class Identity(BaseModel):
    """请求的调用者身份。注入到所有需鉴权路由。"""

    is_authenticated: bool = False
    principal_id: int = 0
    subject: str = "anonymous"
    scopes: list[str] = []
    principal_type: str = ""
    # 动态解析的上游凭据（按身份隔离）
    upstream_provider: str = ""
    upstream_api_key: str | None = None
    upstream_base_url: str = ""


def _anonymous_identity() -> Identity:
    """开发模式：匿名身份，用全局上游配置。"""
    return Identity(
        is_authenticated=False,
        subject="anonymous",
        upstream_api_key=settings.gateway_upstream_api_key or None,
        upstream_base_url=settings.gateway_upstream_base_url,
        upstream_provider="default",
    )


async def get_identity(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> Identity:
    """统一鉴权依赖。

    流程：
    1. 开发模式（无 ENCRYPTION_KEY）→ anonymous
    2. 无 Authorization 头 → 401
    3. 解析 JWT → 校验签名/过期
    4. 查黑名单（revoked）
    5. 查 NhiPrincipal → 解密上游凭据
    """
    # 开发模式降级
    if not is_encryption_enabled():
        return _anonymous_identity()

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header. 获取 token: POST /oauth/token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.removeprefix("Bearer ").strip()

    # 验证 JWT
    try:
        claims = jwt_service.verify_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
        )

    # 检查黑名单
    if await is_revoked(claims["jti"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revoked",
        )

    # 查 NHI principal
    principal = await session.scalar(
        select(NhiPrincipal).where(NhiPrincipal.id == claims["principal_id"])
    )
    if not principal or not principal.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Principal disabled or not found",
        )

    # 解密上游凭据（为空则回退全局配置）
    upstream_key = None
    upstream_url = settings.gateway_upstream_base_url
    upstream_provider = "default"
    if principal.upstream_api_key_enc:
        try:
            upstream_key = decrypt(principal.upstream_api_key_enc)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to decrypt upstream key for %s", principal.client_id)
    if not upstream_key:
        upstream_key = settings.gateway_upstream_api_key or None
    if principal.upstream_base_url:
        upstream_url = principal.upstream_base_url
    if principal.upstream_provider:
        upstream_provider = principal.upstream_provider

    return Identity(
        is_authenticated=True,
        principal_id=principal.id,
        subject=principal.client_id,
        scopes=[s.strip() for s in claims.get("scopes", "").split(",") if s.strip()],
        principal_type=principal.principal_type,
        upstream_provider=upstream_provider,
        upstream_api_key=upstream_key,
        upstream_base_url=upstream_url,
    )


# 便利别名
RequireAuth = Depends(get_identity)
