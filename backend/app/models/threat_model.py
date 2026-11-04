"""威胁建模模型：项目、资产（DFD 元素）、威胁清单、缓解控制。

方法论：经典 STRIDE（S/T/R/I/D/E）+ AI 专属维度（prompt_injection /
data_poisoning / model_inversion / alignment_bypass / loss_of_provenance）。

评分体系：风险 = 可能性(1-5) × 影响(1-5)，范围 1-25。
risk_level: Low(1-4) / Medium(5-9) / High(10-16) / Critical(17-25)。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ThreatProject(Base):
    """威胁建模项目（一个被建模的系统对应一个项目）。"""

    __tablename__ = "threat_projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    # 被建模系统的整体描述
    description: Mapped[str] = mapped_column(Text, default="")
    # draft / active / archived
    status: Mapped[str] = mapped_column(String(16), default="draft", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class Asset(Base):
    """资产 = DFD 元素（外部实体 / 进程 / 数据存储 / 数据流 / 信任边界）。"""

    __tablename__ = "threat_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("threat_projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    # external_entity / process / data_store / data_flow / trust_boundary
    asset_type: Mapped[str] = mapped_column(String(32), default="process", index=True)
    # 技术栈 JSON 数组字符串，如 ["Java/Spring", "PostgreSQL"]
    tech_stack: Mapped[str] = mapped_column(Text, default="[]")
    # 类型相关扩展属性 JSON 字符串（数据流的源/目标等）
    properties: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


class Threat(Base):
    """威胁清单（核心表）。"""

    __tablename__ = "threats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("threat_projects.id", ondelete="CASCADE"), index=True
    )
    # 关联到具体资产（可空，表示全系统级威胁）
    asset_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("threat_assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    # S/T/R/I/D/E + prompt_injection/data_poisoning/model_inversion/alignment_bypass/loss_of_provenance
    category: Mapped[str] = mapped_column(String(32), default="S", index=True)
    likelihood: Mapped[int] = mapped_column(Integer, default=3)
    impact: Mapped[int] = mapped_column(Integer, default=3)
    # Low / Medium / High / Critical（应用层计算后写入）
    risk_level: Mapped[str] = mapped_column(String(16), default="Medium", index=True)
    mitigation: Mapped[str] = mapped_column(Text, default="")
    # open / mitigating / mitigated / accepted
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    # llm_generated / manual
    source: Mapped[str] = mapped_column(String(16), default="manual")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class MitigationControl(Base):
    """缓解控制 = 威胁与现有安全能力之间的联动桥梁。"""

    __tablename__ = "threat_controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("threats.id", ondelete="CASCADE"), index=True
    )
    # detection_rule / audit_evidence / agent_policy / manual
    control_type: Mapped[str] = mapped_column(String(32), default="manual")
    # 引用现有能力的层：lexicon/prompt_guard/llama_guard/dlp/cross_verify/tool_whitelist/rate_limiter/manual
    ref_layer: Mapped[str] = mapped_column(String(32), default="manual")
    # 关联现有规则 ID / 类别代码（如 DlpRule.id、CategoryRule.code），可空
    ref_id: Mapped[str] = mapped_column(String(64), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    # planned / in_effect / verified / failed
    effectiveness: Mapped[str] = mapped_column(String(16), default="planned")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
