"""系统配置管理 API（UI 可改的运行时配置）。

端点：
  GET  /api/config/cross-verify         读取交叉验证配置（API Key 脱敏）
  PUT  /api/config/cross-verify         更新配置（加密存 API Key）
  POST /api/config/cross-verify/test    测试交叉验证模型连接
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..services.config_service import config_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/config", tags=["admin"])


class CrossVerifyConfig(BaseModel):
    """交叉验证配置（API Key 写入时明文，读取时脱敏）。"""

    enabled: bool = Field(False, description="是否启用 L4 交叉验证")
    base_url: str = Field("https://api.openai.com/v1", description="OpenAI 兼容端点")
    api_key: str = Field("", description="API Key（留空表示不修改已有值）")
    model: str = Field("gpt-4o-mini", description="模型名称")


class CrossVerifyConfigRead(BaseModel):
    """交叉验证配置读取（API Key 脱敏）。"""

    enabled: bool
    base_url: str
    api_key_masked: str = Field("", description="脱敏的 API Key（如 sk-***xxx）")
    api_key_set: bool = Field(False, description="是否已设置 API Key")
    model: str


class TestResult(BaseModel):
    success: bool
    latency_ms: int = 0
    detail: str = ""


@router.get("/cross-verify", response_model=CrossVerifyConfigRead)
async def get_cross_verify_config():
    """读取交叉验证配置（API Key 脱敏）。"""
    enabled = await config_service.get_bool("cross_verify.enabled")
    base_url = await config_service.get(
        "cross_verify.base_url", default="https://api.openai.com/v1"
    )
    model = await config_service.get("cross_verify.model", default="gpt-4o-mini")
    api_key = await config_service.get("cross_verify.api_key")

    # 脱敏
    if api_key:
        masked = api_key[:3] + "***" + api_key[-4:] if len(api_key) > 8 else "***"
    else:
        masked = ""

    return CrossVerifyConfigRead(
        enabled=enabled,
        base_url=base_url,
        api_key_masked=masked,
        api_key_set=bool(api_key),
        model=model,
    )


@router.put("/cross-verify", response_model=CrossVerifyConfigRead)
async def update_cross_verify_config(req: CrossVerifyConfig):
    """更新交叉验证配置。

    API Key 为空字符串时保留已有值（不覆盖）。
    """
    await config_service.set("cross_verify.enabled", str(req.enabled).lower(), description="L4 交叉验证开关")
    await config_service.set("cross_verify.base_url", req.base_url, description="交叉验证端点")
    await config_service.set("cross_verify.model", req.model, description="交叉验证模型")

    # API Key：非空才更新（空表示保留）
    if req.api_key:
        await config_service.set(
            "cross_verify.api_key", req.api_key, secret=True, description="交叉验证 API Key"
        )

    await config_service.reload()
    return await get_cross_verify_config()


@router.post("/cross-verify/test", response_model=TestResult)
async def test_cross_verify_connection(req: CrossVerifyConfig):
    """测试交叉验证模型连接（发送一个简单请求验证可达性）。"""
    # 用请求里的配置（或已有的）测试
    base_url = req.base_url.rstrip("/")
    api_key = req.api_key or await config_service.get("cross_verify.api_key")
    model = req.model

    if not api_key:
        return TestResult(success=False, detail="未配置 API Key")

    import time

    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{base_url}/chat/completions",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": 'Reply with exactly: {"unsafe":false,"categories":[],"reason":"test ok"}'}],
                    "max_tokens": 30,
                    "temperature": 0,
                },
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
        latency = int((time.perf_counter() - t0) * 1000)

        if resp.status_code == 200:
            data = resp.json()
            content = (
                data.get("choices", [{}])[0].get("message", {}).get("content", "")[:80]
            )
            return TestResult(success=True, latency_ms=latency, detail=f"连接成功，模型回复: {content}")
        else:
            return TestResult(
                success=False,
                latency_ms=latency,
                detail=f"HTTP {resp.status_code}: {resp.text[:200]}",
            )
    except Exception as e:  # noqa: BLE001
        latency = int((time.perf_counter() - t0) * 1000)
        return TestResult(success=False, latency_ms=latency, detail=f"连接失败: {e}")
