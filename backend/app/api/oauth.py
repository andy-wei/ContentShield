"""OAuth 2.0 Provider 端点。

实现 Client Credentials Grant（适合 Agent 机器身份）：
  POST /oauth/token      — 换取 access token（+ refresh token）
  POST /oauth/revoke     — 撤销 token（黑名单）
  POST /oauth/introspect — 内省 token 状态

未配置 ENCRYPTION_KEY（开发模式）时，/oauth/token 返回 503。
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models.identity import AccessToken, NhiPrincipal, RefreshToken
from ..schemas.identity import (
    IntrospectRequest,
    IntrospectResponse,
    RevokeRequest,
    TokenRequest,
    TokenResponse,
)
from ..security import jwt_service
from ..security.blacklist import revoke as revoke_token
from ..security.crypto import decrypt, encrypt, hash_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["oauth"])


def _require_encryption() -> None:
    """开发模式保护：未配置 ENCRYPTION_KEY 则拒绝。"""
    from ..security.crypto import is_encryption_enabled

    if not is_encryption_enabled():
        raise HTTPException(
            status_code=503,
            detail="NHI 加密未启用。请配置 ENCRYPTION_KEY 环境变量。"
            "生成方法：python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"",
        )


@router.post("/oauth/token", response_model=TokenResponse)
async def issue_token(
    req: TokenRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenResponse:
    """OAuth 2.0 Client Credentials Grant / Refresh Token Grant。"""
    _require_encryption()

    if req.grant_type == "client_credentials":
        principal = await _authenticate_client(req, session)
        return await _create_tokens(principal, session)
    elif req.grant_type == "refresh_token":
        return await _refresh_tokens(req, session)
    else:
        raise HTTPException(status_code=400, detail="unsupported_grant_type")


async def _authenticate_client(
    req: TokenRequest, session: AsyncSession
) -> NhiPrincipal:
    """校验 client_id + client_secret。"""
    if not req.client_id or not req.client_secret:
        raise HTTPException(status_code=400, detail="missing client_id or client_secret")

    principal = await session.scalar(
        select(NhiPrincipal).where(NhiPrincipal.client_id == req.client_id)
    )
    if not principal or not principal.enabled:
        raise HTTPException(status_code=401, detail="invalid_client")

    # 校验 secret（解密比对）
    stored_secret = decrypt(principal.client_secret_enc)
    if stored_secret != req.client_secret:
        raise HTTPException(status_code=401, detail="invalid_client")

    # 更新 last_used_at
    principal.last_used_at = datetime.utcnow()
    await session.commit()
    return principal


async def _create_tokens(
    principal: NhiPrincipal, session: AsyncSession, scope: str | None = None
) -> TokenResponse:
    """为 principal 签发 access + refresh token。"""
    scopes = scope or principal.scopes

    # access token
    access_str, jti, expires_at = jwt_service.create_access_token(
        principal_id=principal.id,
        subject=principal.client_id,
        scopes=scopes,
        principal_type=principal.principal_type,
    )
    session.add(
        AccessToken(
            jti=jti,
            principal_id=principal.id,
            subject=principal.client_id,
            scopes=scopes,
            expires_at=expires_at,
        )
    )

    # refresh token（不透明随机串）
    refresh_str = _gen_refresh()
    refresh_expires = datetime.now(timezone.utc) + timedelta(
        days=settings.refresh_token_ttl_days
    )
    session.add(
        RefreshToken(
            token_hash=hash_token(refresh_str),
            principal_id=principal.id,
            expires_at=refresh_expires,
        )
    )

    await session.commit()

    return TokenResponse(
        access_token=access_str,
        expires_in=settings.access_token_ttl_minutes * 60,
        scope=scopes,
        refresh_token=refresh_str,
    )


def _gen_refresh() -> str:
    """生成 refresh token 明文。"""
    import secrets

    return secrets.token_urlsafe(48)


async def _refresh_tokens(
    req: TokenRequest, session: AsyncSession
) -> TokenResponse:
    """用 refresh token 换新的 access + refresh token。"""
    if not req.refresh_token:
        raise HTTPException(status_code=400, detail="missing refresh_token")

    token_hash = hash_token(req.refresh_token)
    record = await session.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    if not record or record.revoked:
        raise HTTPException(status_code=401, detail="invalid refresh_token")
    # SQLite 存的是 naive datetime，用 naive utcnow 比较
    if record.expires_at.replace(tzinfo=None) < datetime.utcnow():
        raise HTTPException(status_code=401, detail="refresh_token expired")

    # 旧 refresh token 失效（轮换）
    record.revoked = True

    principal = await session.get(NhiPrincipal, record.principal_id)
    if not principal or not principal.enabled:
        raise HTTPException(status_code=401, detail="principal disabled")

    return await _create_tokens(principal, session, req.scope)


@router.post("/oauth/revoke")
async def revoke_endpoint(
    req: RevokeRequest,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """撤销 token（RFC 7009）。"""
    _require_encryption()

    # 尝试作为 access token（JWT）
    try:
        claims = jwt_service.verify_token(req.token)
        ok = await revoke_token(claims["jti"])
        return {"revoked": ok}
    except jwt.InvalidTokenError:
        pass

    # 尝试作为 refresh token
    token_hash = hash_token(req.token)
    record = await session.scalar(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    if record:
        record.revoked = True
        await session.commit()
        return {"revoked": True}

    return {"revoked": False}


@router.post("/oauth/introspect", response_model=IntrospectResponse)
async def introspect_endpoint(
    req: IntrospectRequest,
    session: AsyncSession = Depends(get_session),
) -> IntrospectResponse:
    """Token 内省（RFC 7662）。"""
    _require_encryption()

    try:
        claims = jwt_service.verify_token(req.token)
    except jwt.InvalidTokenError:
        return IntrospectResponse(active=False)

    # 检查黑名单
    from ..security.blacklist import is_revoked

    if await is_revoked(claims["jti"]):
        return IntrospectResponse(active=False)

    return IntrospectResponse(
        active=True,
        scope=claims.get("scopes", ""),
        sub=claims.get("sub"),
        exp=claims.get("exp"),
        client_id=claims.get("sub"),
    )
