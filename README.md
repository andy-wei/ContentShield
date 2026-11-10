<div align="center">

# ContentShield

### AI 安全策略引擎与网关 — 用 AI 保护 AI

基于 Llama-Guard-4-12B 的内容安全系统，提供 7 层纵深防御检测、双向拦截脱敏、动态身份管理与 OpenAI 兼容网关代理。

[快速开始](#-快速开始) · [系统架构](#-系统架构) · [对接指南](#-与其他系统对接) · [API 文档](#-api-参考)

</div>

---

## 📖 项目简介

**ContentShield** 是一个生产级的 AI 内容安全中间件，部署在你的业务系统与 LLM 之间，作为统一的策略执行点。它解决三类核心安全威胁：

| 威胁类型 | 说明 | 防御层 |
|---|---|---|
| **复杂攻击** | 提示词注入、越狱、恶意代码生成、间接注入、MCP 工具描述投毒 | L1 Prompt Guard + L1.5 间接注入 + L2 Llama-Guard + L4 交叉验证 + MCP Guard |
| **HAP** | 仇恨、滥用、脏话 | L0 词库 + L2 Llama-Guard + L4 交叉验证 |
| **机密泄露** | PII、API Key、信用卡、身份证号 | L3 DLP（检测 + 动态脱敏） |
| **危险代码** | LLM 生成/执行 eval、exec、反序列化、SSTI 等代码原语 | L5 CodeShield（静态审计，灵感来自 Meta LlamaFirewall） |

### 核心能力

- 🔍 **7 层纵深防御**：词库 → 注入检测 → 间接注入 → 危害分类 → DLP 防泄露 → 交叉验证 → 代码安全审计
- 🛡️ **AI 网关代理**：OpenAI 兼容，双向拦截（输入 + 输出），自动脱敏改写
- 🤖 **Agent 运行时安全**：工具白名单过滤、危险动作拦截、全量工具调用审计、**行为对齐检测**（AlignmentCheck：无状态轨迹重建 + LLM 判定目标漂移/劫持，灵感来自 Meta LlamaFirewall，判定模型复用 L4 交叉验证配置）、**MCP 工具描述投毒检测**（12 条规则五组：指令覆盖/数据外传/隐藏指令/防护绕过/Prompt 提取；网关内联拦截 + `POST /v1/mcp/audit` 接入前体检，兼容 OpenAI/MCP 双格式）
- 🎯 **威胁建模**：STRIDE + AI 专属维度，LLM 自动生成威胁，控制层证据联动（建模→控制→实际拦截闭环）
- 🔎 **DevSecOps 扫描平台**：编排 bandit/gitleaks/trivy/pip-audit/npm-audit，异步任务队列（Celery+Redis），CI 门禁，漏洞聚合去重与可视化
- 📊 **训练数据安全**：数据集投毒检测（5 类模式）+ PII/有害内容扫描，复用 7 层检测引擎，数据集版本溯源与差异分析
- ⚔️ **红队对抗测试**：自动化攻击生成（预设/模板/LLM）+ Llama-Guard 作为 judge + ASR 评估 + 成员推理攻击（MIA），LLM 安全防御量化评估；**一键导出安全微调训练数据**（成功攻击→DPO 偏好对 / 失败攻击→SFT 正例，打通红队→安全对齐数据飞轮）
- 📦 **模型供应链（MBOM）**：模型物料清单，SHA256 完整性校验，License 合规检查，供应链风险评估，依赖关系追踪
- 🔐 **NHI 动态身份**：OAuth 2.0 令牌、Fernet 加密保险库、按身份隔离上游凭据
- 🧠 **交叉验证**：接入通用大模型（GPT-4o/Claude/DeepSeek）补 Llama-Guard 盲区
- 🧱 **代码安全审计（L5 CodeShield）**：对 LLM 生成/执行代码中的危险原语（eval/exec/反序列化/SSTI/密钥泄露）做静态审计，与 L4 正交互补（L4 管"恶意代码请求"，L5 管"生成的危险代码"），灵感来自 Meta LlamaFirewall，默认关闭、UI 可配 warn/block
- 🎛️ **可视化管理**：策略配置、审计日志、身份管理、威胁建模、安全扫描、训练数据、统计仪表盘
- 🐳 **一键部署**：Docker Compose，支持 cloud / GPU / CPU / Apple Silicon
- ✅ **工程化基座**：pytest + vitest 测试覆盖核心安全逻辑，GitHub Actions CI，ruff + eslint 代码质量门禁

---

## 🏗️ 系统架构

```
用户/Agent ────────► AI 网关 (/v1/chat/completions)
                      │
                      ▼
            ┌─────────────────────┐
            │   7 层检测流水线     │
            │                     │
            │  L0  词库检测        │  脏话/辱骂（微秒级）
            │  L1  Prompt Guard   │  注入/越狱（毫秒级）
            │  L1.5 间接注入       │  工具返回的隐藏指令
            │  L2  Llama-Guard-4  │  S1-S14 危害分类（秒级）
            │  L3  DLP 防泄露      │  PII/密钥/信用卡/URL
            │  L4  交叉验证        │  通用大模型补充意见
            │  L5  CodeShield     │  危险代码原语静态审计
            │                     │
            │  融合决策：          │
            │  block / modify /   │
            │  warn / pass        │
            └────────┬────────────┘
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
     拦截阻断    脱敏改写     放行转发
                  │            │
                  ▼            ▼
              上游 LLM（OpenAI / Azure / 本地）
                     │
                     ▼
            输出端检测 + 脱敏 → 返回客户端
```

### 检测层详解

| 层 | 引擎 | 检测内容 | 速度 | 决策动作 |
|---|---|---|---|---|
| **L0** | 自建词库 | 脏话/辱骂/色情关键词 | 微秒级 | warn |
| **L1** | Prompt Guard 2 86M | 提示词注入/越狱 | 毫秒级 | block |
| **L1.5** | 间接注入检测 | 工具/网页返回的隐藏恶意指令 | 毫秒级 | block |
| **L2** | Llama-Guard-4-12B | S1-S14 内容危害分类 | 秒级 | block/warn |
| **L3** | DLP 正则 | PII/API Key/信用卡/URL 泄露 | 微秒级 | block/modify |
| **L4** | 通用大模型（可选） | HAP/恶意代码/越狱（交叉验证） | 秒级 | warn |
| **L5** | CodeShield 正则（灵感来自 Meta LlamaFirewall） | 生成/执行代码中的危险原语：eval/exec/os.system/subprocess/反序列化/SSTI/PEM 私钥/硬编码 token（16 条内置规则） | 微秒级 | warn/block（UI 可配） |

### 四种决策动作

| 动作 | 含义 | 示例 |
|---|---|---|
| `block` | 拦截，返回拒绝消息 | 注入攻击、API Key 泄露 |
| `modify` | **脱敏后转发** | 手机号 → `[REDACTED-中国手机号]` |
| `warn` | 放行但记录告警 | 低风险 URL、交叉验证补充意见 |
| `pass` | 正常放行 | 无命中 |

### 合规对标：GB/T 45654-2025 风险分类映射

对标《网络安全技术 生成式人工智能服务安全基本要求》（GB/T 45654-2025，2025-11-01 实施）附录 A 的 **5 大类 31 项细分风险**：

| 国标风险大类 | 典型细类 | ContentShield 对应能力 | 覆盖 |
|---|---|---|---|
| A.1 违反社会主义核心价值观 | 暴力、淫秽色情、恐怖极端、武器 | S1 暴力犯罪 + S9 无差别武器 + S12 性内容（L2）；L0 词库（低俗/脏话） | ✅ 强 |
| A.2 歧视性内容 | 民族/信仰/地域/性别/年龄/健康歧视 | S10 仇恨（L2）；L4 交叉验证 HAP | ✅ 强 |
| A.3 商业违法违规 | 商业欺诈、虚假宣传、超范围采集个人信息 | S2 非暴力犯罪（欺诈类）；L3 DLP（个人信息违规处理拦截） | ◐ 部分 |
| A.4 侵犯他人合法权益 | 名誉权、隐私权、个人信息、知识产权 | S5 诽谤 + S7 隐私 + S8 知识产权（L2）；L3 DLP（身份证/手机号/密钥动态脱敏） | ✅ 强 |
| A.5 无法满足特定服务安全需求 | 准确性/可靠性、不当拒答 | L4 交叉验证（部分覆盖事实性核查） | ⚠️ 弱（差距项） |

标准其他章节的对应：**训练数据模块**（投毒 5 类模式 + PII/有害内容扫描）↔ 标准第 5 章"训练数据安全"（来源评估与安全核验、违法不良信息占比红线）；**`scripts/run_benchmark.py`** 的拦截率/误报率评测 ↔ 附录"生成内容安全评估方法"的评测口径。A.3/A.5 的弱覆盖项是后续路线（幻觉核查、商业合规规则库）。

### 检测引擎基准（AdvBench）

默认配置下（Apple Silicon 本地推理，七层引擎）：

| 指标 | 数值 |
|---|---|
| 拦截率（AdvBench 有害集 100 条） | **78%** |
| 误报率（中英干净集 100 条，含 warn） | **0%** |
| 延迟 P50 / P95 / P99 | 1.6s / 2.7s / 2.8s |

完整方法、命中分布、漏网样本分析、冷热引擎对比与复现命令见 [docs/BENCHMARK.md](docs/BENCHMARK.md)（`python3 scripts/run_benchmark.py` 一键复测）。

---

## 🚀 快速开始

### 方式一：Cloud 模式（最简单，无需 GPU）

```bash
# 1. 克隆
git clone https://github.com/你的用户名/ContentShield.git
cd ContentShield

# 2. 配置（至少填 ENCRYPTION_KEY 和 OpenAI Key）
cp .env.example .env

# 生成加密密钥（NHI 身份系统必需）
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# 把输出的密钥填入 .env 的 ENCRYPTION_KEY=

# 3. 启动
docker compose up -d --build

# 4. 打开 http://localhost:5173
```

### 方式二：Apple Silicon 本地模式（Metal GPU 加速）

```bash
# 1. 安装 llama.cpp
brew install llama.cpp

# 2. 下载模型到 models/ 目录
#    - Llama-Guard-4-12B（GGUF 格式）
#    - Llama-Prompt-Guard-2-86M（HF 原始权重）

# 3. 若 GGUF 加载报 MoE 断言错误，运行修复
python3 _fix_gguf.py

# 4. 启动模型服务（Metal 加速）
bash scripts/start_models_mac.sh --daemon

# 5. 启动应用
docker compose -f docker-compose.yml -f docker-compose.host.yml up -d --build
```

### 方式三：NVIDIA GPU（vLLM）

```bash
# 下载模型
huggingface-cli download meta-llama/Llama-Guard-4-12B --local-dir models/Llama-Guard-4-12B

# 启动
docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d --build
```

> 📋 详细配置说明见 [.env.example](.env.example)，每个参数都有注释。

---

## 🔗 与其他系统对接

ContentShield 提供三种接入模式，适配不同场景：

### 模式 A：透明代理（推荐 — 改一行代码即可）

把 ContentShield 当作 OpenAI 的替代地址，**所有请求自动被检测**：

```python
from openai import OpenAI

# 改之前：直连 OpenAI
# client = OpenAI(api_key="sk-xxx", base_url="https://api.openai.com/v1")

# 改之后：经过 ContentShield（改 base_url + 用 NHI token）
client = OpenAI(
    api_key="<NHI_access_token>",        # ContentShield 的 token
    base_url="http://contentshield:8000/v1",
)

# 你的业务代码完全不用改！
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": user_input}]
)
# 自动完成：前置审核 → 脱敏 → 转发 LLM → 后置审核 → 返回
```

**效果**：输入含注入 → 自动拦截；输入含手机号 → 自动脱敏；输出含密钥 → 自动改写。

### 模式 B：API 检测（只检测不转发）

适合审核 UGC 内容、评论过滤等场景：

```python
import requests

CS_URL = "http://contentshield:8000"

# 1. 获取 token（缓存复用，15 分钟有效）
token = requests.post(f"{CS_URL}/oauth/token", json={
    "grant_type": "client_credentials",
    "client_id": "agent-review",
    "client_secret": "your-secret",
}).json()["access_token"]

# 2. 检测内容
result = requests.post(f"{CS_URL}/v1/moderate",
    headers={"Authorization": f"Bearer {token}"},
    json={"text": user_content, "source": "user_prompt"}
).json()

# 3. 根据决策处理
if result["decision"] == "block":
    reject(result["explanations"])       # 拦截
elif result["modified_text"]:
    save(result["modified_text"])        # 用脱敏后的
else:
    save(user_content)                   # 安全
```

### 模式 C：Agent 工具防护（防间接注入）

AI Agent 调用外部工具后，检查返回内容防止间接注入：

```python
# Agent 搜索网页
search_result = agent.call_tool("web_search", query="...")

# 提交检测（防网页里的隐藏指令）
check = requests.post(f"{CS_URL}/v1/tools/moderate",
    headers={"Authorization": f"Bearer {token}"},
    json={"content": search_result, "tool_name": "web_search"}
).json()

if check["decision"] == "block":
    search_result = "搜索结果含可疑内容，已拦截"
elif check.get("modified_text"):
    search_result = check["modified_text"]  # 用脱敏后的

# 安全地喂给 LLM
agent.chat(search_result)
```

### 接入步骤

1. **部署 ContentShield** — 按上方快速开始
2. **颁发 NHI 身份** — 在 UI「身份管理」页为每个业务系统创建独立身份
3. **获取 Token** — 用 client_id + secret 调用 `/oauth/token`
4. **接入业务** — 选择模式 A/B/C，修改你的代码
5. **配置策略** — 在 UI「策略配置」页调整检测规则

---

## 📡 API 参考

### 核心端点

| 端点 | 方法 | 鉴权 | 用途 |
|---|---|---|---|
| `/v1/chat/completions` | POST | NHI Token | **AI 网关代理**（透明转发 + 双向审核） |
| `/v1/moderate` | POST | NHI Token | 纯检测（不转发） |
| `/v1/tools/moderate` | POST | NHI Token | 工具响应检测（防间接注入） |
| `/v1/mcp/audit` | POST | NHI Token | MCP 工具描述投毒审计（接入前逐工具体检） |
| `/api/moderate` | POST | 无 | UI 检测台用（内部） |

### OAuth / 身份

| 端点 | 方法 | 用途 |
|---|---|---|
| `/oauth/token` | POST | 获取 access token（Client Credentials Grant） |
| `/oauth/revoke` | POST | 撤销 token |
| `/oauth/introspect` | POST | 查询 token 状态 |

### 管理 API（`/api` 前缀）

| 端点 | 用途 |
|---|---|
| `/api/nhi/principals` | NHI 身份 CRUD（含工具白名单配置） |
| `/api/rules/categories` | 危害类别开关 |
| `/api/rules/lexicon` | 敏感词库管理 |
| `/api/rules/dlp` | DLP 正则规则管理 |
| `/api/config/cross-verify` | L4 交叉验证配置（UI 可改） |
| `/api/config/code-shield` | L5 代码安全配置（开关 + warn/block 动作，UI 可改） |
| `/api/config/alignment-check` | 行为对齐检测配置（开关 + 动作 + 可选 LLM 覆盖，默认复用交叉验证模型） |
| `/api/config/security` | 安全策略（限流阈值/爆破防护/管理鉴权开关） |
| `/api/config/dangerous-tools` | 危险工具黑名单管理 |
| `/api/config/threat-model` | 威胁建模 LLM 配置 |
| `/api/threat-model/*` | 威胁建模全套 CRUD（项目/资产/威胁/控制/LLM 生成/证据） |
| `/api/audit-checklist` | OWASP LLM Top 10 审计 checklist（查询/状态更新/摘要） |
| `/api/scan/targets` | 扫描目标管理（git/path/image） |
| `/api/scan/jobs` | 触发/查询扫描任务（Celery 异步） |
| `/api/scan/jobs/{id}/findings` | 漏洞 finding 分页查询（按严重度/工具过滤） |
| `/api/scan/jobs/{id}/gate` | CI 门禁判定（pass/fail） |
| `/api/scan/policies` | 门禁策略 CRUD |
| `/api/scan/upload` | CI 端上传扫描结果 |
| `/api/training/datasets` | 训练数据集上传与管理（JSONL/CSV/TXT） |
| `/api/training/datasets/{id}/scan` | 触发数据集安全扫描（复用 7 层引擎 + 投毒检测） |
| `/api/training/scans/{id}/findings` | 问题样本查询（按问题类型/投毒类型过滤） |
| `/api/training/scans/{id}/report` | 扫描报告（问题分布、风险分布、Top 样本） |
| `/api/redteam/campaigns` | 红队对抗测试活动管理 |
| `/api/redteam/campaigns/{id}/results` | 攻击结果查询（含 ASR 统计） |
| `/api/redteam/campaigns/{id}/report` | 红队报告（ASR、类别分布、成功攻击、风险洞察） |
| `/api/redteam/campaigns/{id}/export-training` | 导出训练数据 JSONL（fmt=dpo 偏好对 / sft 正例，红队→安全微调数据飞轮） |
| `/api/mbom/artifacts` | 模型制品登记与管理 |
| `/api/mbom/artifacts/{id}/verify` | 模型文件完整性校验 |
| `/api/mbom/artifacts/{id}/risk` | 供应链风险评估 |
| `/api/mbom/export` | MBOM 完整导出（CycloneDX-like） |
| `/api/audit` | 审计日志查询 + CSV 导出 |
| `/api/audit/agent-actions` | Agent 工具调用审计 |
| `/api/stats/*` | 统计仪表盘数据 |

### 检测响应示例

```json
{
  "decision": "modify",
  "risk_score": 0.45,
  "modified_text": "联系我 [REDACTED-中国手机号]",
  "categories": ["pii:中国手机号"],
  "explanations": ["L3 DLP: 已脱敏 1 处敏感信息"],
  "layers": {
    "lexicon":       {"hit": false, "decision": "pass"},
    "prompt_guard":  {"hit": false, "decision": "pass"},
    "llama_guard":   {"hit": false, "decision": "pass"},
    "dlp":           {"hit": true,  "decision": "modify"},
    "indirect_injection": {"hit": false, "decision": "skipped"},
    "cross_verify":  {"hit": false, "decision": "skipped"},
    "code_shield":   {"hit": false, "decision": "skipped"}
  },
  "latency_ms": 52
}
```

完整 API 文档：启动后访问 `http://localhost:8000/docs`（Swagger UI）。

---

## 📋 OWASP LLM Top 10 审计 Checklist

把 [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/) 的 10 类风险固化为可逐项审计的 checklist，每项含审计要点、检查方法、对应检测层、状态跟踪。

### 覆盖的 10 类风险

| 编号 | 风险 | 对应检测层 | 检查方法 |
|---|---|---|---|
| LLM01 | Prompt Injection（提示注入） | L1 Prompt Guard | 代码审计 |
| LLM02 | Sensitive Information Disclosure（信息泄露） | L3 DLP | 代码审计 |
| LLM03 | Supply Chain（供应链） | MBOM | 工具扫描 |
| LLM04 | Data and Model Poisoning（数据投毒） | 训练数据扫描 | 工具扫描 |
| LLM05 | Improper Output Handling（输出处理不当） | L2 Llama-Guard | 代码审计 |
| LLM06 | Excessive Agency（过度代理） | 工具白名单 | 代码审计 |
| LLM07 | System Prompt Leakage（系统提示泄露） | L1 Prompt Guard | 渗透测试 |
| LLM08 | Vector and Embedding Weaknesses（向量弱点） | 间接注入检测 | 代码审计 |
| LLM09 | Misinformation（错误信息/幻觉） | L4 交叉验证 | 代码审计 |
| LLM10 | Unbounded Consumption（无界消耗/DoS） | 限流 | 配置检查 |

### 审计流程

每项 checklist 状态流转：`pending`（待审计）→ `pass`（通过）/ `fail`（不通过）/ `na`（不适用），记录审计证据与审计人。系统启动时自动 seed 这 10 项（幂等），并提供通过率摘要（排除 na 项）。

每项的审计要点直接对应可操作的检查项，如 LLM01 的要点包括"间接注入：工具返回内容是否经过检测后再喂给 LLM"、"系统 prompt 是否与用户输入严格分离"等。

---

## 🔎 DevSecOps 扫描平台

DevSecOps 扫描平台编排开源安全工具（bandit/gitleaks/trivy/pip-audit/npm-audit），覆盖 SAST、SCA、密钥扫描、镜像扫描、IaC 配置检测，提供统一的漏洞聚合、去重、CI 门禁与可视化。

### 架构

```
CI/手动触发
    │
    ▼
POST /api/scan/jobs ──► Celery Worker ──► 拉取目标(git clone/路径/镜像)
                          │
                          ▼
                    依次跑各工具适配器
                    (bandit/gitleaks/trivy/pip-audit/npm)
                          │
                          ▼
                    跨工具去重 + 指纹计算
                          │
                          ▼
                    落库 Finding + 回填统计
                          │
                          ▼
GET /api/scan/jobs/{id}/gate ──► 门禁判定(pass/fail)
```

### 工具覆盖

| 工具 | 类别 | 检测内容 |
|---|---|---|
| bandit | SAST | Python 静态安全反模式（subprocess shell、eval、硬编码密码等） |
| semgrep | SAST | 多语言 SAST（预留） |
| gitleaks | secret | 代码中的密钥/凭证泄露（API Key、Token、私钥） |
| trivy | container/config/secret | 容器镜像漏洞 + IaC 配置问题 + 密钥扫描 |
| pip-audit | SCA | Python 依赖已知 CVE |
| npm audit | SCA | 前端依赖已知 CVE |

### CI 集成（cs-scan CLI）

`cs-scan` 在 CI 本地跑工具，把结果上传到平台并查询门禁：

```bash
# 安装
pip install -e "./backend[dev]"

# 跑扫描并上传 + 门禁判定（失败则退出码 1）
cs-scan --target . --tools bandit,gitleaks,pip-audit \
        --server http://contentshield:8000 --gate
```

GitHub Actions 集成（仓库自带 Action）：

```yaml
- uses: ./.github/actions/cs-scan
  with:
    target: .
    tools: bandit,gitleaks,pip-audit
    server: ${{ secrets.CS_SERVER_URL }}
    gate: true
```

### 门禁策略

默认策略：存在 Critical 漏洞或超过 5 个 High 漏洞时阻断 CI。可在 UI「安全扫描」页或 `/api/scan/policies` 自定义各严重度阈值。

---

## 📊 训练数据安全扫描

对 LLM 训练/微调/知识库数据集进行安全扫描，检测投毒样本、PII 泄露、有害内容。**核心架构亮点：复用运行时 7 层检测引擎**——同一套检测能力服务推理（运行时）和训练（数据集），避免两套独立系统。

### 检测能力

| 检测项 | 来源 | 说明 |
|---|---|---|
| **PII 泄露** | 复用 L3 DLP | 手机号/身份证/API Key/信用卡/邮箱 |
| **有害内容** | 复用 L2 Llama-Guard | S1-S14 危害分类 |
| **注入攻击** | 复用 L1 Prompt Guard | 提示词注入/越狱 |
| **投毒：指令注入** | 训练专属 | "忽略之前指令"等注入语句 |
| **投毒：角色覆盖** | 训练专属 | 伪造 system 角色标记 |
| **投毒：隐蔽触发词** | 训练专属 | 零宽字符/base64/hex 编码块 |
| **投毒：重复模式** | 训练专属 | 同一短语重复 ≥5 次（强化学习信号） |
| **投毒：格式异常** | 训练专属 | 超长单行/控制字符比例异常 |

### 数据集溯源

- **样本哈希**：每条样本 SHA256，用于跨次扫描去重与溯源
- **数据集指纹**：所有样本哈希的聚合哈希，用于版本对比
- **版本差异**：对比两个版本的新增/删除/修改样本

### 支持格式

- **JSONL**：每行一个 JSON，提取 `text`/`content`/`messages`/`prompt+completion` 字段
- **CSV**：每行一条记录，提取 `text`/`content`/`prompt` 等列
- **TXT**：每行一条记录

---

## ⚔️ LLM 红队对抗测试

自动化探测目标 LLM 的安全弱点，量化评估模型的越狱防御能力。**核心架构亮点：复用 Llama-Guard 作为 judge**——攻击生成 + 推理检测引擎作为裁判，形成"攻击→目标→判定"闭环。

### 工作流程

```
攻击生成器 ──► 攻击 prompt ──► 目标 LLM ──► 回复 ──► Llama-Guard judge
     │                                                    │
     │                                                    ▼
     │                                           unsafe? (越狱成功)
     │                                                    │
     ▼                                                    ▼
三类来源                                          ASR = 成功数/总数
1. 预设测试集（HarmBench/AdvBench 子集）
2. 参数化模板（DAN/角色扮演/base64/payload splitting）
3. LLM 自动红队（基于目标回复迭代生成更强攻击）
```

### 攻击类别

| 类别 | 说明 | 示例策略 |
|---|---|---|
| **jailbreak** | 越狱 | DAN、角色扮演、FreedomGPT、fictional framing |
| **prompt_injection** | 提示注入 | system override、payload splitting |
| **social_engineering** | 社会工程 | 权威伪装、grandma exploit、prefix injection |
| **encoding** | 编码绕过 | base64、translation bypass |
| **harmful_request** | 直接有害请求 | 安全研究伪装 |

### ASR 评估

- **ASR（Attack Success Rate）**= 成功越狱数 / 总攻击数

### 导出训练数据（红队 → 安全对齐数据飞轮）

红队发现不止于评估报告——一键转化为安全微调训练数据（`GET /campaigns/{id}/export-training`，UI 报告页按钮）：

- **DPO 偏好对**（成功攻击）：`{prompt, chosen, rejected, meta}`——`rejected` 为目标模型真实屈服回复，`chosen` 为按攻击类别定制、多模板轮换合成的安全拒绝；格式兼容 HF `trl` DPOTrainer
- **SFT 正例**（失败攻击）：`{prompt, completion}`——模型真实安全回复，格式兼容训练数据模块的扫描器（可回传扫描形成闭环）

配合后续微调（如用偏好对 DPO 训练自有 guard 模型）即构成「红队发现 → 数据构造 → 对齐训练 → ASR 复测」的完整安全数据飞轮。
- judge 判定：目标回复被 Llama-Guard 判为 `block` 或 `warn` → 攻击成功
- 按类别统计 ASR，识别最脆弱的攻击维度
- 多次 campaign 对比可评估模型安全改进趋势

### 成员推理攻击（Membership Inference Attack, MIA）

评估模型是否泄露**训练数据的成员关系**——攻击者通过观察模型响应，判断某条数据是否参与了训练。

**原理**：模型对训练时见过的数据（member）会产生更自信的响应（更短、措辞更确定）。即使不返回 logprob，响应特征也是有效的代理信号。

**流程**：
1. 发送 20 个探针（10 个高频通用句作为 member，10 个独特/特定句作为 non-member）
2. 提取每个响应的隐私特征（长度、确定性启发式分数、延迟）
3. 统计分析：计算 **MI Advantage**（攻击者通过响应特征区分 member 的准确率超出随机猜测的部分）
4. 风险分级：low（<5%）/ medium / high / critical（>25%）

```
50% MI Advantage = 完全无法区分 = 模型防御好（理想）
>50% = 存在隐私泄露，训练数据可被推断
```

**防御启示**：差分隐私训练（DP-SGD）、置信度屏蔽（温度平滑）、模型蒸馏。

API：`POST /api/redteam/membership-inference` 发起，`GET /api/redteam/membership-inference/{id}` 查询结果。

---

## 📦 模型供应链安全（MBOM）

模型物料清单（Model Bill of Materials），类比 SBOM 但面向 AI 模型，覆盖部署供应链安全：来源验证、哈希完整性、License 合规、风险评估。

### 安全维度

| 维度 | 检测内容 | 风险评分 |
|---|---|---|
| **来源** | HuggingFace / 内部 / 自定义，验证上传者可信度 | +10~30 |
| **完整性** | SHA256 哈希校验，检测文件是否被篡改 | +20(未校验)~40(篡改) |
| **License** | 合规检查：宽松(MIT/Apache) / 注意(Llama) / 限制(GPL/NC) / 未知 | +10~25 |
| **签名** | cosign 等工具签名验证 | +15(未签名)~35(失败) |
| **依赖** | 模型间依赖追踪（LoRA → base model） | — |

### 完整性校验

```bash
# 登记模型时自动计算 SHA256
POST /api/mbom/artifacts  # {name, source, file_path, ...}

# 后续校验文件是否被篡改
POST /api/mbom/artifacts/{id}/verify  # → {verified: true/false, message}
```

### 风险评估

每个模型制品自动计算供应链风险分（0-100），分级 low/medium/high/critical，并给出具体的风险项与修复建议。MBOM 导出（`GET /api/mbom/export`）提供全量制品清单 + 风险摘要。

---

## 🧩 配置说明

关键配置项（`.env` 文件）：

| 配置 | 必填 | 说明 |
|---|---|---|
| `ENCRYPTION_KEY` | ✅ | Fernet 主密钥（NHI/加密必需） |
| `INFERENCE_PROFILE` | ✅ | `cloud` / `local-gpu` / `local-cpu` |
| `GATEWAY_UPSTREAM_API_KEY` | ✅ | 上游 LLM 的 API Key |
| `GATEWAY_UPSTREAM_BASE_URL` | ✅ | 上游 LLM 地址 |
| `GATEWAY_MODE` | | `pre` / `post` / `both`（默认双向审核） |
| `CROSS_VERIFY_*` | | L4 交叉验证（可在 UI 配置，无需改文件） |

> 💡 L4 交叉验证支持在 UI「系统设置」页直接配置（填入 API Key + 模型名即可），无需修改 `.env` 或重启。

---

## 🖥️ 管理界面

启动后访问 **http://localhost:5173**：

| 页面 | 功能 |
|---|---|
| **仪表盘** | 检测统计、趋势图、类别/层级分布 |
| **检测台** | 粘贴文本实时测试 7 层检测 |
| **策略配置** | 类别开关、词库管理、DLP 规则 |
| **威胁建模** | STRIDE + AI 维度威胁建模，LLM 自动生成威胁，控制层证据联动 |
| **审计 Checklist** | OWASP LLM Top 10（2025）逐项审计，映射检测层，通过率跟踪 |
| **安全扫描** | DevSecOps 漏洞扫描，多工具聚合，CI 门禁，finding 可视化 |
| **训练数据** | 训练/微调数据集安全扫描，投毒检测，PII/有害内容，版本溯源 |
| **红队测试** | LLM 对抗测试，攻击生成，Llama-Guard judge，ASR 评估 |
| **模型供应链** | 模型物料清单（MBOM），哈希完整性，License 合规，风险评估 |
| **审计日志** | 检测记录（含身份归因）、Agent 动作审计、CSV 导出 |
| **网关配置** | OpenAI 兼容代理使用说明 |
| **身份管理** | NHI 颁发、OAuth Token 测试、凭据轮转、工具白名单配置 |
| **系统设置** | 推理后端状态、L4 交叉验证配置、L5 代码安全配置、安全策略（限流/爆破防护）、威胁建模 LLM 配置 |

---

## 🗂️ 项目结构

```
ContentShield/
├── backend/                    # FastAPI 后端
│   └── app/
│       ├── api/                # 路由层
│       │   ├── moderate.py     #   检测端点
│       │   ├── proxy.py        #   AI 网关代理（含 Agent 安全拦截）
│       │   ├── tools.py        #   工具响应检测（防间接注入）
│       │   ├── oauth.py        #   OAuth 2.0 Provider
│       │   ├── admin_nhi.py    #   NHI 管理
│       │   ├── admin_rules.py  #   策略管理
│       │   ├── admin_audit.py  #   审计查询（含 Agent 动作审计）
│       │   ├── admin_config.py #   系统配置（含安全策略/工具黑名单）
│       │   ├── threat_model.py #   威胁建模 API（项目/资产/威胁/控制/证据）
│       │   └── stats.py        #   统计
│       ├── engine/             # 检测引擎
│       │   ├── orchestrator.py #   7 层编排器
│       │   ├── stream_processor.py  # 流式处理
│       │   └── detectors/      #   7 个检测器
│       ├── inference/          # 推理后端抽象
│       ├── security/           # 加密/JWT/黑名单/限流
│       │   ├── tool_policy.py  #   Agent 工具白名单 + 危险动作拦截
│       │   ├── rate_limiter.py #   滑动窗口限流 + 暴力破解锁定
│       │   ├── jwt_service.py  #   JWT 签发与验证
│       │   └── crypto.py       #   Fernet 加密 + 凭据生成
│       ├── services/
│       │   ├── config_service.py        # 动态配置（DB 持久化 + 缓存）
│       │   ├── threat_model_service.py  # 威胁建模服务（LLM 生成 + 证据聚合）
│       │   └── scan_service.py          # DevSecOps 扫描服务
│       ├── scan/                        # 扫描子系统
│       │   ├── tools/                   #   工具适配器（bandit/gitleaks/trivy/pip-audit/npm）
│       │   ├── runner.py                #   扫描执行器（拉代码→跑工具→去重→落库）
│       │   ├── celery_app.py            #   Celery 应用（异步任务队列）
│       │   ├── dedup.py                 #   跨工具 finding 去重
│       │   └── cli.py                   #   cs-scan 命令行（CI 集成）
│       ├── training/                    # 训练数据安全子系统
│       │   ├── dataset_scanner.py       #   批量扫描器（复用 orchestrator + 投毒检测）
│       │   ├── poison_patterns.py       #   5 类投毒检测（注入/角色覆盖/隐蔽触发/重复/格式）
│       │   └── provenance.py            #   数据集溯源（哈希/指纹/版本对比）
│       ├── redteam/                     # LLM 红队对抗测试子系统
│       │   ├── attack_generators.py     #   攻击生成（预设测试集/模板/LLM 自动红队）
│       │   ├── judge.py                 #   评估器（复用 Llama-Guard 作为 judge）
│       │   ├── target_client.py         #   目标模型客户端（复用 _OpenAICompatibleBackend）
│       │   └── runner.py                #   红队执行器（生成→攻击→判定→落库）
│       ├── mbom/                        # 模型供应链安全子系统
│       │   └── generator.py             #   哈希/完整性/license/模型卡解析/风险评估
│       ├── models/             # ORM 模型（threat_model / agent_action / scan / training / redteam / mbom）
│       └── schemas/            # Pydantic 模型
├── backend/tests/              # pytest 测试（核心安全逻辑覆盖 91-100%）
├── frontend/                   # React + Vite + TS + Tailwind
│   └── src/
│       ├── pages/              #   8 个页面（含威胁建模）
│       ├── api/                #   API 封装
│       ├── store/              #   状态管理
│       ├── components/         #   通用组件
│       └── lib/                #   工具函数
├── frontend/tests/             # vitest 测试（format/Card/Badge）
├── inference/                  # 推理服务
│   ├── prompt_guard_server.py  #   Prompt Guard Python 服务
│   ├── vllm/Dockerfile         #   vLLM 服务
│   └── llama-cpp/Dockerfile    #   llama.cpp 服务
├── .github/workflows/ci.yml    # GitHub Actions CI（后端 ruff+pytest / 前端 lint+tsc+vitest+build）
├── data/                       # 词库/正则规则
├── scripts/                    # 模型下载/启动脚本
├── docker-compose.yml          # 基础编排
├── docker-compose.gpu.yml      # GPU 模式
├── docker-compose.cpu.yml      # CPU 模式
├── docker-compose.host.yml     # Apple Silicon 宿主机模式
└── .env.example                # 配置模板
```

---

## 🔐 安全设计

| 设计 | 说明 |
|---|---|
| **凭据零明文** | client_secret 和上游 API Key 用 Fernet 加密存储 |
| **Token 短生命周期** | access token 15 分钟过期，降低泄露风险 |
| **即时撤销** | JWT 黑名单，发现异常 token 可立即拉黑 |
| **按身份隔离上游** | 每个 NHI 可绑定不同上游凭据（OpenAI/Azure/Anthropic） |
| **Agent 工具白名单** | 每个 NHI 独立工具白名单，危险工具（命令执行/删库/转账）内置黑名单拦截 |
| **限流 + 暴力破解防护** | IP+路径滑动窗口限流，OAuth 端点失败计数 + 临时锁定 |
| **审计身份归因** | 每次检测记录调用者身份（principal_id + subject） |
| **Agent 动作审计** | 全量工具调用落库，参数自动脱敏，可查询被拦截动作 |
| **审计 PII 打码** | 审计库不存储原始 PII，避免二次泄露 |
| **双向脱敏** | 输入端和输出端都支持自动脱敏改写 |
| **威胁建模证据联动** | 威胁建模的控制层映射到运行时检测层，反向聚合实际拦截数据形成闭环 |

---

## 🧪 工程化与质量保障

项目配备了完整的质量保障基座，确保安全逻辑的正确性可被验证：

| 维度 | 工具 | 覆盖范围 |
|---|---|---|
| **后端单测** | pytest + pytest-asyncio + pytest-cov | 核心安全模块（jwt/crypto/rate_limiter/tool_policy）覆盖率 91-100%，检测器纯逻辑 60-80%，威胁建模 LLM 解析与风险评分 |
| **前端单测** | vitest + @testing-library/react | format.ts 纯函数、Card/Badge 组件渲染与样式 |
| **后端 Lint** | ruff（check + format） | 风格统一 + pyflakes 真实 bug 检测 + isort 导入排序 |
| **前端 Lint** | eslint + prettier | TypeScript 类型安全 + React Hooks 规则 + 代码格式化 |
| **类型检查** | tsc --noEmit | 前端全量类型检查 |
| **CI/CD** | GitHub Actions | push/PR 自动跑后端 ruff+pytest、前端 lint+tsc+vitest+build，失败阻断合并 |

```bash
# 本地一键验证（与 CI 一致）
cd backend && ruff check app/ && ruff format app/ --check && pytest
cd frontend && npm run lint && npx tsc --noEmit && npm run test && npm run build
```

---

## 📚 技术栈

| 层 | 技术 |
|---|---|
| 后端 | FastAPI + SQLAlchemy 2.0 + Pydantic v2 |
| 前端 | React 18 + TypeScript + Vite + TailwindCSS + Recharts |
| 推理 | llama.cpp（Metal/CUDA）+ Python transformers（MPS） |
| 安全 | Fernet 加密 + JWT（HS256）+ OAuth 2.0 |
| DevSecOps | Celery + Redis 异步任务队列 + bandit/gitleaks/trivy/pip-audit |
| 部署 | Docker Compose（多 profile） |

---

## 📖 技术参考

- [Llama-Guard-4-12B 模型卡](https://huggingface.co/meta-llama/Llama-Guard-4-12B)
- [Llama Guard 4 官方 Prompt 格式](https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-4/)
- [Llama Prompt Guard 2 86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- [vLLM OpenAI 兼容服务](https://docs.vllm.ai/en/stable/serving/openai_compatible_server/)
- [OAuth 2.0 Client Credentials Grant (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- [Token Revocation (RFC 7009)](https://datatracker.ietf.org/doc/html/rfc7009)

---

## 📄 License

MIT
