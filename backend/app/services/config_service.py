"""动态配置服务：从 SystemConfig 表读写运行时配置（无需重启）。

特性：
- 敏感字段（is_secret=True）用 Fernet 加密存储
- 内存缓存（修改时失效），避免每次请求查库
- .env 的静态配置作为默认值/回退

用法：
    from app.services.config_service import config_service
    enabled = await config_service.get("cross_verify.enabled", default="false")
    api_key = await config_service.get("cross_verify.api_key", secret=True)
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from ..db import async_session
from ..models.system_config import SystemConfig
from ..security.crypto import decrypt, encrypt

logger = logging.getLogger(__name__)


class ConfigService:
    """运行时配置服务（带内存缓存）。"""

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}
        self._loaded = False

    async def _ensure_loaded(self) -> None:
        """首次访问时全量加载到缓存。"""
        if self._loaded:
            return
        await self.reload()

    async def reload(self) -> None:
        """重新加载所有配置到缓存（配置修改后调用）。"""
        async with async_session() as session:
            result = await session.execute(select(SystemConfig))
            rows = result.scalars().all()
        self._cache = {}
        for row in rows:
            # 敏感字段解密后缓存
            if row.is_secret and row.value_enc:
                try:
                    self._cache[row.key] = decrypt(row.value_enc)
                except Exception:  # noqa: BLE001
                    self._cache[row.key] = ""
            else:
                self._cache[row.key] = row.value
        self._loaded = True
        logger.info("SystemConfig loaded: %d keys", len(self._cache))

    async def get(self, key: str, default: str = "") -> str:
        """读取配置值（从缓存）。"""
        await self._ensure_loaded()
        return self._cache.get(key, default)

    async def get_bool(self, key: str, default: bool = False) -> bool:
        """读取布尔配置。"""
        val = await self.get(key, str(default).lower())
        return val.lower() in ("true", "1", "yes", "on")

    async def set(self, key: str, value: str, *, secret: bool = False, description: str = "") -> None:
        """写入配置（敏感字段加密）。"""
        async with async_session() as session:
            existing = await session.scalar(
                select(SystemConfig).where(SystemConfig.key == key)
            )
            if existing:
                if secret:
                    existing.value_enc = encrypt(value) if value else ""
                    existing.value = ""  # 敏感不存明文
                else:
                    existing.value = value
                existing.is_secret = secret
                if description:
                    existing.description = description
            else:
                row = SystemConfig(
                    key=key,
                    value="" if secret else value,
                    value_enc=encrypt(value) if (secret and value) else "",
                    is_secret=secret,
                    description=description,
                )
                session.add(row)
            await session.commit()
        # 更新缓存
        self._cache[key] = value

    async def set_many(self, items: dict[str, tuple[str, bool]]) -> None:
        """批量写入。items: {key: (value, is_secret)}。"""
        for key, (value, secret) in items.items():
            await self.set(key, value, secret=secret)
        await self.reload()

    async def has(self, key: str) -> bool:
        await self._ensure_loaded()
        return key in self._cache

    def get_cached(self, key: str, default: str = "") -> str:
        """同步读取（从缓存，不查库）。需先 ensure_loaded。"""
        return self._cache.get(key, default)


# 全局单例
config_service = ConfigService()
