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
    # 加载动态配置（SystemConfig）+ seed 安全策略默认值
    from .services.config_service import config_service

    await config_service.reload()
    await config_service.ensure_defaults({
        "security.oauth_max_attempts": "5",
        "security.oauth_lockout_minutes": "15",
        "security.rate_limit_oauth": "10",
        "security.rate_limit_api": "60",
        "security.rate_limit_admin": "120",
        "security.admin_token_required": "false",
        "security.dangerous_tools": "",
    })
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


# ---- 全局限流中间件 ----
@app.middleware("http")
async def rate_limit_middleware(request, call_next):
    """按 (IP, 路径前缀) 限流，超限返回 429。"""
    from .security.client import get_client_ip
    from .security.rate_limiter import rate_limiter
    from .services.config_service import config_service

    path = request.url.path
    # 健康检查/docs 不限流
    if path in ("/healthz", "/", "/docs", "/openapi.json", "/redoc"):
        return await call_next(request)

    ip = get_client_ip(request)

    # 按路径前缀选限流策略
    if path.startswith("/oauth"):
        max_req = int(await config_service.get("security.rate_limit_oauth", "10"))
        rate_key = f"rate:oauth:{ip}"
    elif path.startswith("/v1/"):
        max_req = int(await config_service.get("security.rate_limit_api", "60"))
        rate_key = f"rate:api:{ip}"
    elif path.startswith("/api/"):
        max_req = int(await config_service.get("security.rate_limit_admin", "120"))
        rate_key = f"rate:admin:{ip}"
    else:
        return await call_next(request)  # 其他路径不限流

    allowed, remaining = rate_limiter.check_rate(rate_key, max_req, window_sec=60.0)
    if not allowed:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=429,
            content={"detail": "请求过于频繁，请稍后再试"},
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit": str(max_req),
                "X-RateLimit-Remaining": "0",
            },
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(max_req)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response


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
