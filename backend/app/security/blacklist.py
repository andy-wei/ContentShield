"""Token 黑名单管理：撤销状态查询与执行。

基于 AccessToken 表的 revoked 字段。撤销时标记 revoked=True，
验证时查库确认。过期 token 由后台清理任务自动删除。
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select, update

from ..db import async_session
from ..models.identity import AccessToken


async def is_revoked(jti: str) -> bool:
    """检查 token 是否已撤销。"""
    async with async_session() as session:
        result = await session.execute(
            select(AccessToken.revoked).where(AccessToken.jti == jti)
        )
        row = result.first()
        # token 不在表中（旧版/外部签发）默认未撤销；存在则看 revoked 字段
        return bool(row and row[0])


async def revoke(jti: str) -> bool:
    """撤销 token（加入黑名单）。返回是否成功。"""
    async with async_session() as session:
        result = await session.execute(
            update(AccessToken)
            .where(AccessToken.jti == jti)
            .values(revoked=True)
        )
        await session.commit()
        return result.rowcount > 0  # type: ignore[attr-defined]


async def cleanup_expired() -> int:
    """清理过期 token（删除已过期的记录）。返回删除数。"""
    now = datetime.now(timezone.utc)
    async with async_session() as session:
        from sqlalchemy import delete

        result = await session.execute(
            delete(AccessToken).where(AccessToken.expires_at < now)
        )
        await session.commit()
        return result.rowcount  # type: ignore[attr-defined]
