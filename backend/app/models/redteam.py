"""LLM 红队对抗测试数据模型：活动、攻击用例、攻击结果。

设计要点：
- Campaign：一次红队活动，配置目标模型 + 攻击生成策略
- AttackCase：单条攻击 prompt（来源：preset/template/llm）
- AttackResult：攻击结果（目标回复 + judge 判定 + 是否越狱成功）
- ASR（Attack Success Rate）= 成功越狱数 / 总攻击数
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class RedteamCampaign(Base):
    """一次红队对抗测试活动。"""

    __tablename__ = "redteam_campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    # 目标模型配置 JSON：{base_url, api_key(加密), model, temperature, max_tokens}
    target_config: Mapped[str] = mapped_column(Text, default="{}")
    # 攻击生成策略 JSON：{source: preset/template/llm, count, categories[], llm_config}
    strategy: Mapped[str] = mapped_column(Text, default="{}")
    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    # 总攻击数
    total_attacks: Mapped[int] = mapped_column(Integer, default=0)
    # 成功越狱数
    success_count: Mapped[int] = mapped_column(Integer, default=0)
    # ASR = success_count / total_attacks
    asr: Mapped[float] = mapped_column(Float, default=0.0)
    # 进度 0-100
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    celery_task_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class AttackCase(Base):
    """单条攻击用例。"""

    __tablename__ = "redteam_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("redteam_campaigns.id", ondelete="CASCADE"), index=True
    )
    # 攻击 prompt
    prompt: Mapped[str] = mapped_column(Text)
    # 攻击来源：preset / template / llm
    source: Mapped[str] = mapped_column(String(16), default="preset", index=True)
    # 攻击类别：jailbreak / prompt_injection / harmful_request / encoding / social_engineering
    category: Mapped[str] = mapped_column(String(32), default="jailbreak", index=True)
    # 模板名（source=template 时）
    template_name: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class AttackResult(Base):
    """单次攻击的结果。"""

    __tablename__ = "redteam_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("redteam_cases.id", ondelete="CASCADE"), index=True
    )
    campaign_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("redteam_campaigns.id", ondelete="CASCADE"), index=True
    )
    # 目标模型的回复
    response: Mapped[str] = mapped_column(Text, default="")
    # judge 判定：是否为不安全内容（越狱成功）
    judged_unsafe: Mapped[int] = mapped_column(Integer, default=0)  # 0/1
    # judge 识别的类别（如 S1 暴力、S7 仇恨）
    judged_category: Mapped[str] = mapped_column(String(64), default="")
    # judge 的原始判定
    judge_raw: Mapped[str] = mapped_column(Text, default="")
    # 响应延迟（毫秒）
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    # 是否攻击成功（judge 判定 unsafe 即成功）
    success: Mapped[int] = mapped_column(Integer, default=0, index=True)  # 0/1
    # 错误信息（如目标模型超时）
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
