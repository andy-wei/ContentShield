"""数据库会话与初始化（SQLAlchemy 2.0 异步 + SQLite）。"""
from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import settings


def _build_engine():
    url = settings.database_url
    kwargs: dict = {"echo": False}
    if url.startswith("sqlite"):
        # SQLite：用 pysqlite DBAPI 的 connect 事件开启 WAL 与外键。
        # 注意 event.listens_for 必须针对真实目标（engine 实例），
        # 因此先建 engine，再注册监听器。
        engine = create_async_engine(url, **kwargs)

        @event.listens_for(engine.sync_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return engine
    return create_async_engine(url, **kwargs)


engine = _build_engine()
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。"""


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI 依赖：每请求一个会话。"""
    async with async_session() as session:
        yield session


async def init_db() -> None:
    """建表 + 轻量迁移（开发期用；生产应走 Alembic 迁移）。

    create_all 只建新表不修改旧表，这里补一个简单的 ALTER TABLE 迁移，
    为已存在表添加新增列（SQLite 支持 ADD COLUMN）。
    """
    from . import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_auto_migrate)


def _auto_migrate(connection) -> None:
    """轻量自动迁移：为旧表补新增列。"""
    from sqlalchemy import inspect, text

    inspector = inspect(connection)
    # 迁移规则：{table: [(column_name, column_type_sql)]}
    migrations = {
        "audit_logs": [
            ("principal_id", "INTEGER"),
            ("subject", "VARCHAR(128) DEFAULT ''"),
            ("scopes", "VARCHAR(256) DEFAULT ''"),
        ],
    }
    for table, columns in migrations.items():
        if not inspector.has_table(table):
            continue
        existing = {c["name"] for c in inspector.get_columns(table)}
        for col_name, col_type in columns:
            if col_name not in existing:
                try:
                    connection.execute(
                        text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                    )
                except Exception:  # noqa: BLE001
                    pass  # 列已存在或其他 SQLite 限制
