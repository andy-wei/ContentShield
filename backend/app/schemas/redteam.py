"""LLM 红队对抗测试的 Pydantic 请求/响应模型。"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

CampaignStatus = Literal["pending", "running", "completed", "failed"]
AttackSource = Literal["preset", "template", "llm"]
AttackCategory = Literal[
    "jailbreak",
    "prompt_injection",
    "harmful_request",
    "encoding",
    "social_engineering",
]


# ==================== 目标模型配置 ====================


class TargetConfig(BaseModel):
    """待测目标模型的配置。"""

    base_url: str = "https://api.openai.com/v1"
    api_key: str = ""
    model: str = "gpt-4o-mini"
    temperature: float = 0.7
    max_tokens: int = 512


# ==================== 攻击策略 ====================


class AttackStrategy(BaseModel):
    """攻击生成策略。"""

    # preset / template / llm / mixed
    source: Literal["preset", "template", "llm", "mixed"] = "preset"
    # 生成攻击数量
    count: int = Field(10, ge=1, le=200)
    # 攻击类别筛选（空=全部）
    categories: list[AttackCategory] = Field(default_factory=list)
    # LLM 生成器配置（source=llm/mixed 时需要）
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"


# ==================== Campaign ====================


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = ""
    target: TargetConfig
    strategy: AttackStrategy


class CampaignOut(BaseModel):
    id: int
    name: str
    description: str
    target_config: dict
    strategy: dict
    status: CampaignStatus
    total_attacks: int
    success_count: int
    asr: float
    progress: int
    error: str
    celery_task_id: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_json(cls, campaign) -> CampaignOut:
        """从 ORM 构造，解析 JSON 配置字段。"""
        import json

        data = {c.name: getattr(campaign, c.name) for c in campaign.__table__.columns}
        for field in ("target_config", "strategy"):
            try:
                data[field] = json.loads(data.get(field) or "{}")
            except (json.JSONDecodeError, TypeError):
                data[field] = {}
        return cls.model_validate(data)


# ==================== 攻击用例 + 结果 ====================


class AttackCaseOut(BaseModel):
    id: int
    campaign_id: int
    prompt: str
    source: AttackSource
    category: AttackCategory
    template_name: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AttackResultOut(BaseModel):
    id: int
    case_id: int
    campaign_id: int
    response: str
    judged_unsafe: bool
    judged_category: str
    judge_raw: str
    latency_ms: int
    success: bool
    error: str
    created_at: datetime
    # 关联的攻击用例（详情查询时携带）
    case: AttackCaseOut | None = None

    model_config = {"from_attributes": True}


class AttackResultList(BaseModel):
    """分页攻击结果。"""

    items: list[AttackResultOut]
    total: int
    # 按类别统计成功率
    category_stats: dict[str, dict]  # {category: {total, success, asr}}


# ==================== 报告 ====================


class CampaignReport(BaseModel):
    """红队活动汇总报告。"""

    campaign: CampaignOut
    # 整体 ASR
    overall_asr: float
    # 按类别分布
    category_breakdown: dict[str, dict]
    # 成功攻击 Top N
    top_successful_attacks: list[AttackResultOut]
    # 最危险的攻击模式
    risk_insights: list[str]
