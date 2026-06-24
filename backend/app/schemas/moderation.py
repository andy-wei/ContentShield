"""审核相关的请求/响应模型。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ModerationRequest(BaseModel):
    """POST /v1/moderate 请求。"""

    text: str = Field(..., description="待检测文本")
    source: Literal[
        "user_prompt", "llm_response", "gateway", "tool_response", "test"
    ] = Field("user_prompt", description="来源标识，用于审计分组")
    # 可选对话上下文（多轮场景，仅取最后一条做检测但保留上下文）
    context: list[dict] | None = Field(
        None, description='对话上下文 [{"role":"user","content":"..."}]'
    )
    # 是否跳过审计落库（用于健康检查/批量测试）
    skip_audit: bool = Field(False, description="跳过审计落库")

    model_config = {"json_schema_extra": {"example": {"text": "测试内容", "source": "test"}}}


class LayerResult(BaseModel):
    """单层检测结果。"""

    name: str = Field(..., description="层名 lexicon/prompt_guard/llama_guard/dlp/indirect_injection")
    hit: bool = Field(False, description="是否命中")
    decision: Literal["pass", "warn", "modify", "block", "skipped"] = "pass"
    # 命中详情（每层结构不同，灵活 dict）
    details: dict = Field(default_factory=dict)
    latency_ms: int = 0


class ModerationResponse(BaseModel):
    """POST /v1/moderate 响应。"""

    decision: Literal["pass", "warn", "modify", "block"]
    risk_score: float = Field(..., ge=0.0, le=1.0, description="综合风险评分")
    layers: dict[str, LayerResult]
    categories: list[str] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)
    modified_text: str | None = Field(
        None, description="脱敏后文本（仅 modify 决策时返回）"
    )
    latency_ms: int = 0
