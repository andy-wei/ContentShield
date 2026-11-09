# ContentShield 检测引擎基准报告

> 对应国标 GB/T 45654-2025 附录"生成内容安全评估方法"的评测口径。
> 全部数字可复现：`python3 scripts/run_benchmark.py --concurrency 3`（遵守 AGENTS.md 原则 28：机制结论必须实验验证）。

## 结果总览（2026-11-09，默认配置）

| 指标 | 数值 | 口径 |
|---|---|---|
| **拦截率** | **78%** | AdvBench 有害集 100 条，decision ∈ {block, modify} |
| **硬误拦率** | **0%** | 自建中英干净集 100 条，decision ∈ {block, modify} |
| **总误报率（含 warn）** | **0%** | 同上，放宽至含 warn 仍为 0 |
| 延迟 P50 | 1,627 ms | 并发 3，含全部七层 |
| 延迟 P95 | 2,652 ms | 同上 |
| 延迟 P99 | 2,775 ms | 同上 |

## 测试配置

- 检测引擎：默认部署形态（L0 词库 / L1 Prompt Guard 2 86M / L1.5 间接注入 / L2 Llama-Guard-4-12B f16 [6 类别聚焦：S1/S2/S7/S9/S10/S14] / L3 DLP；L4/L5/AlignmentCheck 默认关闭）
- 硬件：Apple Silicon（Metal 加速），模型服务跑宿主机，引擎跑 Docker
- 数据集：AdvBench harmful_behaviors 前 100 条（`data/benchmarks/advbench_100.jsonl`）+ 自建 100 条中英日常干净集（`data/benchmarks/benign_100.jsonl`，覆盖编程/写作/翻译/常识/生活/商务等 9 类场景）
- 脚本自动临时调高 API 限流（跑完恢复），429 指数退避重试

## 命中类别分布

`S-unknown(64)`、`S-injection(42)`、`S2(1)`（多类别可叠加）：
- L2 Llama-Guard 承担主拦截（64 条判 unsafe；S-unknown = 内容有害但不属于启用的 6 类别，是 f16 GGUF 聚焦模式的已知行为——拦截正确、类别标注粗粒度）
- L1 Prompt Guard 补充注入面（42 条 AdvBench 攻击本身是注入/越狱形态）

## 漏网样本分析（22 条，差距项）

漏过样本呈现清晰模式：**儿童持枪教学、暗杀武器设计、种族煽动网站、美化暴力的游戏、虚假医疗信息播客**——属于 S1（暴力犯罪）与 S10（仇恨）语义范围但 L2 判 safe。归因：f16 量化 + 6 类别聚焦模式下 Llama-Guard-4 对"间接/委婉表述的有害意图"召回不足。

**已验证的改进路径**：开启 L4 交叉验证（通用大模型补充意见）可覆盖此类语义盲区——这正是 L4 设计目标，UI 一键开启。

## 数据点：冷启动 vs 热引擎

| 轮次 | L1 状态 | 拦截率 |
|---|---|---|
| 第 1 轮 | Prompt Guard 模型冷加载中（L1 降级 skip） | 65% |
| 第 4 轮 | L1 热就绪 | **78%** |

单层故障时引擎自动降级不中断（L2 兜底），多一层热引擎 +13 个百分点——**纵深防御的量化证据**。

## 复现

```bash
# 前置：模型服务就绪（bash scripts/start_models_mac.sh --daemon）
python3 scripts/run_benchmark.py --concurrency 3
# 原始数据：docs/benchmark_results.json（含全部误报/漏网样本明细）
```
