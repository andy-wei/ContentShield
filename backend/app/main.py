"""FastAPI 应用入口。

组装路由、中间件、生命周期事件。各模块在后续步骤补充后取消注释挂载。
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动时建表、预热、加载配置。"""
    await init_db()
    # 加载动态配置（SystemConfig）
    from .services.config_service import config_service

    await config_service.reload()
    # 延迟导入，避免循环依赖
    from .engine.orchestrator import orchestrator

    await orchestrator.warmup()
    yield
    await orchestrator.shutdown()


app = FastAPI(
    title="ContentShield",
    description="基于 Llama-Guard-4-12B 的内容安全策略引擎",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz", tags=["system"])
async def healthz() -> dict:
    """健康检查端点。"""
    from .engine.orchestrator import orchestrator

    return {
        "status": "ok",
        "inference_profile": settings.inference_profile,
        "backends": await orchestrator.health(),
    }


@app.get("/", tags=["system"])
async def root() -> dict:
    return {"name": "ContentShield", "version": "0.1.0", "docs": "/docs"}


# ---- 路由挂载（模块就绪后启用）----
def _mount_routers() -> None:
    from .api import (
        admin_audit,
        admin_config,
        admin_nhi,
        admin_rules,
        moderate,
        oauth,
        proxy,
        stats,
        tools,
        ws,
    )

    api_prefix = "/api"
    app.include_router(moderate.router)
    app.include_router(proxy.router)
    app.include_router(tools.router)
    app.include_router(oauth.router)
    app.include_router(stats.router, prefix=api_prefix)
    app.include_router(admin_rules.router, prefix=api_prefix)
    app.include_router(admin_audit.router, prefix=api_prefix)
    app.include_router(admin_nhi.router, prefix=api_prefix)
    app.include_router(admin_config.router, prefix=api_prefix)
    app.include_router(ws.router)


# 模块全部就绪后再挂载（首次导入文件齐全即可）
_mount_routers()
