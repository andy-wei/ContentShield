"""模型供应链安全（MBOM）子系统。

类比 SBOM（软件物料清单），但面向 AI 模型：
- 模型哈希与完整性校验
- 模型卡元数据解析（HuggingFace model card）
- License 合规检查
- 依赖关系追踪（LoRA → base model）
- 供应链风险评估
"""
