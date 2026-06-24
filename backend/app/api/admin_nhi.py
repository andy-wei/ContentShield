"""NHI（非人类身份）管理 API。

端点：
  POST   /api/nhi/principals              创建 NHI（返回一次性明文 secret）
  GET    /api/nhi/principals              列表
  DELETE /api/nhi/principals/{id}         删除/禁用
  POST   /api/nhi/principals/{id}/rotate-secret  轮转 secret
  GET    /api/nhi/tokens                  活跃 token 列表
  POST   /api/nhi/tokens/{jti}/revoke     撤销 token
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models.identity import AccessToken, NhiPrincipal
from ..schemas.identity import (
    NhiPrincipalCreate,
    NhiPrincipalCreated,
    NhiPrincipalRead,
    SecretRotated,
)
from ..security.crypto import (
    decrypt,
    encrypt,
    generate_client_id,
    generate_client_secret,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/nhi", tags=["admin"])


@router.get("/principals", response_model=list[NhiPrincipalRead])
async def list_principals(session: AsyncSession = Depends(get_session)):
    res = await session.execute(select(NhiPrincipal).order_by(NhiPrincipal.id.desc()))
    return res.scalars().all()


@router.post("/principals", response_model=NhiPrincipalCreated, status_code=201)
async def create_principal(
    req: NhiPrincipalCreate,
    session: AsyncSession = Depends(get_session),
) -> NhiPrincipalCreated:
    """创建 NHI。明文 secret 仅此一次返回。"""
    from ..security.crypto import is_encryption_enabled

    if not is_encryption_enabled():
        raise HTTPException(
            status_code=503,
            detail="需先配置 ENCRYPTION_KEY 才能创建 NHI",
        )

    principal_type = req.principal_type
    client_id = generate_client_id(principal_type)
    client_secret = generate_client_secret()

    # 加密上游凭据（若提供）
    upstream_enc = ""
    if req.upstream_api_key:
        upstream_enc = encrypt(req.upstream_api_key)

    principal = NhiPrincipal(
        client_id=client_id,
        client_secret_enc=encrypt(client_secret),
        label=req.label,
        principal_type=principal_type,
        scopes=req.scopes,
        upstream_provider=req.upstream_provider or "",
        upstream_api_key_enc=upstream_enc,
        upstream_base_url=req.upstream_base_url or "",
    )
    session.add(principal)
    await session.commit()
    await session.refresh(principal)

    return NhiPrincipalCreated(
        id=principal.id,
        client_id=principal.client_id,
        client_secret=client_secret,
        label=principal.label,
        principal_type=principal.principal_type,
        scopes=principal.scopes,
        created_at=principal.created_at,
    )


@router.delete("/principals/{principal_id}", status_code=204)
async def delete_principal(
    principal_id: int,
    session: AsyncSession = Depends(get_session),
):
    """禁用 NHI（设置 enabled=False，保留记录用于审计）。"""
    principal = await session.get(NhiPrincipal, principal_id)
    if not principal:
        raise HTTPException(status_code=404, detail="not found")
    principal.enabled = False
    await session.commit()


@router.post("/principals/{principal_id}/rotate-secret", response_model=SecretRotated)
async def rotate_secret(
    principal_id: int,
    session: AsyncSession = Depends(get_session),
) -> SecretRotated:
    """轮转 client_secret。旧 secret 立即失效。"""
    principal = await session.get(NhiPrincipal, principal_id)
    if not principal:
        raise HTTPException(status_code=404, detail="not found")

    new_secret = generate_client_secret()
    principal.client_secret_enc = encrypt(new_secret)
    await session.commit()

    return SecretRotated(
        id=principal.id, client_id=principal.client_id, client_secret=new_secret
    )


@router.get("/tokens")
async def list_tokens(
    only_active: bool = True,
    session: AsyncSession = Depends(get_session),
):
    """活跃 token 列表。"""
    from datetime import datetime

    stmt = select(AccessToken).order_by(AccessToken.id.desc())
    if only_active:
        now = datetime.utcnow()
        stmt = stmt.where(
            AccessToken.revoked.is_(False), AccessToken.expires_at >= now
        )
    stmt = stmt.limit(100)
    res = await session.execute(stmt)
    return [
        {
            "id": t.id,
            "jti": t.jti[:12] + "...",
            "principal_id": t.principal_id,
            "subject": t.subject,
            "scopes": t.scopes,
            "expires_at": t.expires_at.isoformat(),
            "revoked": t.revoked,
            "created_at": t.created_at.isoformat(),
        }
        for t in res.scalars().all()
    ]


@router.post("/tokens/{jti}/revoke")
async def revoke_token_endpoint(
    jti: str,
    session: AsyncSession = Depends(get_session),
):
    """撤销指定 token。jti 可以是完整值或前缀。"""
    from sqlalchemy import update

    # 支持前缀匹配（前端列表里 jti 被截断显示）
    stmt = update(AccessToken)
    if jti.endswith("..."):
        stmt = stmt.where(AccessToken.jti.like(jti[:-3] + "%"))
    else:
        stmt = stmt.where(AccessToken.jti == jti)
    stmt = stmt.values(revoked=True)
    result = await session.execute(stmt)
    await session.commit()
    return {"revoked": result.rowcount > 0}  # type: ignore[attr-defined]
