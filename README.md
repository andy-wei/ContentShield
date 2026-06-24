<div align="center">

# ContentShield

### AI 安全策略引擎与网关 — 用 AI 保护 AI

基于 Llama-Guard-4-12B 的内容安全系统，提供 6 层纵深防御检测、双向拦截脱敏、动态身份管理与 OpenAI 兼容网关代理。

[快速开始](#-快速开始) · [系统架构](#-系统架构) · [对接指南](#-与其他系统对接) · [API 文档](#-api-参考)

</div>

---

## 📖 项目简介

**ContentShield** 是一个生产级的 AI 内容安全中间件，部署在你的业务系统与 LLM 之间，作为统一的策略执行点。它解决三类核心安全威胁：

| 威胁类型 | 说明 | 防御层 |
|---|---|---|
| **复杂攻击** | 提示词注入、越狱、恶意代码生成、间接注入 | L1 Prompt Guard + L1.5 间接注入 + L2 Llama-Guard + L4 交叉验证 |
| **HAP** | 仇恨、滥用、脏话 | L0 词库 + L2 Llama-Guard + L4 交叉验证 |
| **机密泄露** | PII、API Key、信用卡、身份证号 | L3 DLP（检测 + 动态脱敏） |

### 核心能力

- 🔍 **6 层纵深防御**：词库 → 注入检测 → 间接注入 → 危害分类 → DLP 防泄露 → 交叉验证
- 🛡️ **AI 网关代理**：OpenAI 兼容，双向拦截（输入 + 输出），自动脱敏改写
- 🔐 **NHI 动态身份**：OAuth 2.0 令牌、Fernet 加密保险库、按身份隔离上游凭据
- 🧠 **交叉验证**：接入通用大模型（GPT-4o/Claude/DeepSeek）补 Llama-Guard 盲区
- 🎛️ **可视化管理**：策略配置、审计日志、身份管理、统计仪表盘
- 🐳 **一键部署**：Docker Compose，支持 cloud / GPU / CPU / Apple Silicon

---

## 🏗️ 系统架构

```
用户/Agent ────────► AI 网关 (/v1/chat/completions)
                      │
                      ▼
            ┌─────────────────────┐
            │   6 层检测流水线     │
            │                     │
            │  L0  词库检测        │  脏话/辱骂（微秒级）
            │  L1  Prompt Guard   │  注入/越狱（毫秒级）
            │  L1.5 间接注入       │  工具返回的隐藏指令
            │  L2  Llama-Guard-4  │  S1-S14 危害分类（秒级）
            │  L3  DLP 防泄露      │  PII/密钥/信用卡/URL
            │  L4  交叉验证        │  通用大模型补充意见
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

### 四种决策动作

| 动作 | 含义 | 示例 |
|---|---|---|
| `block` | 拦截，返回拒绝消息 | 注入攻击、API Key 泄露 |
| `modify` | **脱敏后转发** | 手机号 → `[REDACTED-中国手机号]` |
| `warn` | 放行但记录告警 | 低风险 URL、交叉验证补充意见 |
| `pass` | 正常放行 | 无命中 |

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
| `/api/nhi/principals` | NHI 身份 CRUD |
| `/api/rules/categories` | 危害类别开关 |
| `/api/rules/lexicon` | 敏感词库管理 |
| `/api/rules/dlp` | DLP 正则规则管理 |
| `/api/config/cross-verify` | L4 交叉验证配置（UI 可改） |
| `/api/audit` | 审计日志查询 + CSV 导出 |
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
    "cross_verify":  {"hit": false, "decision": "skipped"}
  },
  "latency_ms": 52
}
```

完整 API 文档：启动后访问 `http://localhost:8000/docs`（Swagger UI）。

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
| **检测台** | 粘贴文本实时测试 6 层检测 |
| **策略配置** | 类别开关、词库管理、DLP 规则 |
| **审计日志** | 检测记录（含身份归因）、CSV 导出 |
| **网关配置** | OpenAI 兼容代理使用说明 |
| **身份管理** | NHI 颁发、OAuth Token 测试、凭据轮转 |
| **系统设置** | 推理后端状态、L4 交叉验证配置 |

---

## 🗂️ 项目结构

```
ContentShield/
├── backend/                    # FastAPI 后端
│   └── app/
│       ├── api/                # 路由层
│       │   ├── moderate.py     #   检测端点
│       │   ├── proxy.py        #   AI 网关代理
│       │   ├── tools.py        #   工具响应检测
│       │   ├── oauth.py        #   OAuth 2.0 Provider
│       │   ├── admin_nhi.py    #   NHI 管理
│       │   ├── admin_rules.py  #   策略管理
│       │   ├── admin_audit.py  #   审计查询
│       │   ├── admin_config.py #   系统配置
│       │   └── stats.py        #   统计
│       ├── engine/             # 检测引擎
│       │   ├── orchestrator.py #   6 层编排器
│       │   ├── stream_processor.py  # 流式处理
│       │   └── detectors/      #   6 个检测器
│       ├── inference/          # 推理后端抽象
│       ├── security/           # 加密/JWT/黑名单
│       ├── models/             # ORM 模型
│       └── schemas/            # Pydantic 模型
├── frontend/                   # React + Vite + TS + Tailwind
│   └── src/
│       ├── pages/              #   7 个页面
│       ├── api/                #   API 封装
│       ├── store/              #   状态管理
│       └── components/         #   通用组件
├── inference/                  # 推理服务
│   ├── prompt_guard_server.py  #   Prompt Guard Python 服务
│   ├── vllm/Dockerfile         #   vLLM 服务
│   └── llama-cpp/Dockerfile    #   llama.cpp 服务
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
| **审计身份归因** | 每次检测记录调用者身份（principal_id + subject） |
| **审计 PII 打码** | 审计库不存储原始 PII，避免二次泄露 |
| **双向脱敏** | 输入端和输出端都支持自动脱敏改写 |

---

## 📚 技术栈

| 层 | 技术 |
|---|---|
| 后端 | FastAPI + SQLAlchemy 2.0 + Pydantic v2 |
| 前端 | React 18 + TypeScript + Vite + TailwindCSS + Recharts |
| 推理 | llama.cpp（Metal/CUDA）+ Python transformers（MPS） |
| 安全 | Fernet 加密 + JWT（HS256）+ OAuth 2.0 |
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
