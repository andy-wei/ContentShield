# Guard 模型微调报告：从部署者到生产者

> 面向岗位方向 1（Guardrail 模型后训练）的实战项目：用红队数据飞轮的产出，
> LoRA 微调 Qwen3-1.7B 训练自己的注入检测 guard，与生产中使用的 Prompt Guard 2 对比。
> 全流程可复现（AGENTS.md 原则 28）。

## 结论速览

| 模型 | Accuracy | INJECTION P/R/F1 | JAILBREAK F1 | 备注 |
|---|---|---|---|---|
| **自训 Guard（Qwen3-1.7B-4bit + LoRA）** | **97.9%**（47/48） | 1.00 / 1.00 / **1.00** | 0.97 | 489 样本，4 分钟训练，峰值内存 3.5GB |
| Prompt Guard 2 86M（生产基线） | 50.0% | 0.81 / 0.62 / 0.65 | 0*（二分类变体） | 中文注入漏检 8/21 |

*本地部署的 Prompt Guard 2 服务仅输出 BENIGN/INJECTION 两类，JAILBREAK 类不支持，该项天然为 0。

**核心发现：中文注入场景下，通用 Prompt Guard 2 召回率仅 62%；300+ 中文/混合样本 LoRA 微调的 1.7B guard 达到 100% 召回**——印证"领域定制 guard 显著优于通用小分类器"的假设，且成本极低（4 分钟 / 3.5GB / 单卡 Apple Silicon）。

## 方法

### 数据（`scripts/build_guard_dataset.py` 一键重建）

489 条三分类 SFT（JAILBREAK 161 / INJECTION 218 / BENIGN 110，90/10 分层划分）：

| 标签 | 来源 | 规模 |
|---|---|---|
| JAILBREAK | AdvBench 100（英文）+ 手写中文越狱库 60（`data/training/zh_jailbreak.py`，覆盖 9 类攻击形态） | 160 |
| INJECTION | 20 个注入指令内核 × 10 种真实载体（网页/邮件/PDF/工具返回/工单/RSS，中英）参数化生成 + MCP 投毒描述 | 218 |
| BENIGN | 引擎基准干净集 100 + 工具/文档场景扩充 | 110 |

另产出 100 对 DPO 偏好对（AdvBench goal + target 屈服开头作 rejected + 拒绝模板作 chosen，复用红队模块的 `refusal_templates`）。

### 训练（`scripts/train_guard_sft.sh`）

- 底座：Qwen3-1.7B（ModelScope 下载，本地 mlx_lm.convert 转 4bit MLX，923MB）
- LoRA：16 层，rank 默认，batch 4，lr 1e-5，400 iters（约 3 个 epoch）
- 硬件：Apple Silicon M 系 + 64GB，MLX 后端，**全程 4 分钟，峰值内存 3.5GB**
- 收敛：train loss 0.681→0.136，val loss 0.534→0.289（无过拟合）

### 评估（`scripts/eval_guard.py`）

同一 48 条验证集，双方盲测。自训 guard 以生成式输出解析单标签；Prompt Guard 2 走生产同款 `/v1/classify` API。

## 诚实局限（面试必问，先自己说）

1. **同分布偏置**：验证集与训练集同分布（模板×载体生成），自训模型占优部分来自分布熟悉。结论表述应为"领域分布上的定制价值"，不是通用能力全面超越。
2. **验证集规模小**：48 条，统计功效有限；INJECTION 满分有噪声成分。
3. **Prompt Guard 2 的 JAILBREAK 缺失**是本地部署变体所致（0.31 服务版二分类），对比对其不利；但中文注入召回差距（62% vs 100%）在 INJECTION 类内是同类对比，结论稳健。
4. 生成式 guard 单条推理 ~200ms 级，慢于专用分类器（~50ms）——部署需权衡（或蒸馏回分类器头部，后续工作）。

## 复现

```bash
python3 scripts/build_guard_dataset.py        # 重建数据集
bash scripts/train_guard_sft.sh              # 4 分钟训练
python scripts/eval_guard.py \
  --model models/qwen3-1.7b-4bit-mlx \
  --adapter models/adapters/guard-sft-qwen3-1.7b   # 对比评估
```

原始数据：`docs/guard_eval_results.json`（含完整混淆矩阵）。

## 后续路线

- DPO 阶段：用 100 对偏好对在 SFT 基础上继续对齐（`guard_dpo.jsonl` 已就绪）
- 独立测试集：换 seed 重新生成 + 人工标注 50 条，消除同分布偏置质疑
- 蒸馏部署：1.7B 生成式 → 分类头蒸馏，兼顾精度与 50ms 延迟
- 接回 ContentShield：训练出的 guard 作为可插拔 L1 后端（`prompt_guard_backend` 配置项）
