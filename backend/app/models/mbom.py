"""模型供应链安全（MBOM）数据模型：模型制品 + 模型依赖。

设计要点：
- ModelArtifact：一个模型制品（权重文件/完整模型包），含来源、哈希、license、签名状态
- ModelDependency：模型间的依赖关系（如 LoRA adapter 依赖 base model）
- 类比 SBOM（软件物料清单），但面向 AI 模型，覆盖部署供应链安全
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class ModelArtifact(Base):
    """模型制品（一个权重文件或完整模型包）。"""

    __tablename__ = "mbom_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    # 模型类型：base / fine_tuned / lora_adapter / embedding / guard
    model_type: Mapped[str] = mapped_column(String(32), default="base", index=True)
    # 来源：huggingface / internal / openai / anthropic / custom
    source: Mapped[str] = mapped_column(String(32), default="huggingface", index=True)
    # 来源标识（HF repo id、内部路径、API model name）
    source_id: Mapped[str] = mapped_column(String(256), default="")
    # 版本/commit
    version: Mapped[str] = mapped_column(String(64), default="")
    # 文件路径（本地存储的权重路径，相对 data_dir）
    file_path: Mapped[str] = mapped_column(String(512), default="")
    # 文件大小（字节）
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    # SHA256 哈希（完整性校验）
    sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    # License（MIT/Apache-2.0/proprietary/unknown）
    license: Mapped[str] = mapped_column(String(64), default="unknown")
    # 签名状态：unsigned / signed / verified / failed
    signature_status: Mapped[str] = mapped_column(String(16), default="unsigned", index=True)
    # 完整性状态：unknown / verified / tampered
    integrity_status: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    # 模型卡元数据 JSON：{description, author, training_data, capabilities, limitations, ...}
    model_card: Mapped[str] = mapped_column(Text, default="{}")
    # 安全评估 JSON：{toxicity_bias, adversarial_tested, privacy_assessed}
    security_assessment: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class ModelDependency(Base):
    """模型间的依赖关系。"""

    __tablename__ = "mbom_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # 依赖方模型（如 LoRA adapter）
    artifact_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("mbom_artifacts.id", ondelete="CASCADE"), index=True
    )
    # 被依赖的模型（如 base model）
    depends_on_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("mbom_artifacts.id", ondelete="CASCADE"), index=True
    )
    # 依赖类型：base_model / tokenizer / vocab / config
    dependency_type: Mapped[str] = mapped_column(String(32), default="base_model")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
