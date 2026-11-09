# ContentShield 简历素材（AI 安全求职）

> 本文档是项目的求职素材库：可直接粘贴的简历模板、面试展开用的 STAR 故事、
> 量化数据与 Q&A 预案。数据全部真实可复现（见「量化数据」节）。

---

## 一、简历项目栏模板（3 行版，空间紧张时用）

> **ContentShield — AI 安全策略引擎与网关**（独立设计开发 · Python/FastAPI/React/Docker）
> 基于 Llama-Guard-4-12B 的 7 层纵深防御内容安全系统 + OpenAI 兼容网关：双向拦截与动态脱敏、
> NHI 动态身份（OAuth 2.0/JWT/Fernet）、Agent 运行时安全（工具白名单/危险动作拦截/行为对齐检测，
> 对标 Meta LlamaFirewall 三大扫描器全部自研落地）；436 项测试，CI/CD 双流水线，真实 LLM 端到端验证。

## 二、简历项目栏模板（5 行完整版）

> **ContentShield — AI 安全策略引擎与网关**（独立设计开发 · Python/FastAPI/React/Docker · GitHub: andy-wei/ContentShield）
> - **7 层纵深防御检测引擎**：词库 → PromptGuard 注入检测 → 间接注入 → Llama-Guard-4 危害分类 →
>   DLP 动态脱敏 → 通用大模型交叉验证 → CodeShield 代码安全审计；并行编排 + 结果缓存，融合决策
>   block/modify/warn/pass 四级动作，PII 命中智能降级（脱敏替代误拦）
> - **AI 网关与 Agent 运行时安全**：OpenAI 兼容代理，输入/输出双向拦截 + 流式 SSE 缓冲审核；
>   NHI 维度工具白名单、危险动作黑名单、行为对齐检测（无状态轨迹重建 + LLM 判定目标漂移/劫持）
> - **NHI 动态身份体系**：OAuth 2.0 Client Credentials、15 分钟短时 JWT、Fernet 凭据加密保险库、
>   按身份隔离上游密钥、爆破锁定与分层限流
> - **工程化**：pytest 436 项全绿、GitHub Actions 双流水线（CI + DevSecOps 自举扫描——用系统自身的
>   扫描平台扫描自身代码）、ruff/eslint 门禁；真实 LLM（qwen:7b）端到端验证漂移拦截

---

## 三、核心技术亮点（面试展开用 STAR）

### 亮点 1：LlamaFirewall 三大扫描器的自研落地（差异化最强）

Meta 的 LlamaFirewall 定义了 Agent 安全三大能力：PromptGuard（注入检测）、CodeShield（代码安全）、
AlignmentCheck（行为对齐）。本项目将其**全部落地为生产可用组件**：

- **PromptGuard**：L1 层，Prompt Guard 2 86M（DeBERTa-v2）+ 自建间接注入模式库（L1.5）
- **CodeShield（L5）**：16 条内置规则静态审计 LLM 生成代码中的危险原语（eval/exec/反序列化/SSTI/
  密钥泄露），零侵入接入——复用编排器并行 gather，新增一层仅 5 行接线；与 L4 交叉验证正交互补
  （L4 拦"恶意代码请求"，L5 拦"生成的危险代码"）
- **AlignmentCheck（最深）**：检测 Agent 多步执行中的目标漂移/劫持。**架构创新：无状态轨迹重建**——
  利用 OpenAI 协议"客户端每轮重发完整 messages"的特性，从请求历史直接重建意图（首条 user 消息）
  与动作序列（历史 tool_calls），替代 LlamaFirewall 的服务端 trace 存储，规避了同一身份多会话
  污染与状态丢失问题；结论缓存（轨迹哈希，5min TTL）控制 LLM 调用成本

**面试问「为什么不用服务端存会话轨迹」的答法**：三个理由——①协议特性决定了全量历史每请求自带，
服务端存储是冗余；②按 principal 存 trace 会让同一 Agent 的多个并发会话互相污染，需要额外发明
session_id 机制；③无状态重启不丢、水平扩展无需共享存储。代价是客户端截断历史时意图退化为
"最早可见的 user 消息"——工程上可接受，因为截断通常保留任务主线。

### 亮点 2：纵深防御的层次化决策融合

七层并行检测后由编排器融合：block > modify > warn > pass；各层权重差异化（间接注入 0.4 最高）。
**PII 智能降级**：当 block 仅来自 LlamaGuard 的泄露误报且 DLP 层有精确脱敏命中时，自动降级为
modify（如用户输信用卡号咨询 → 脱敏转发而非粗暴拒绝）；注入类攻击的 block 永不降级。

### 亮点 3：网关形态的安全执行点

OpenAI 兼容代理，业务系统零改造接入。三个执行阶段：前置内容审核（输入+工具返回的间接注入防御）→
Agent 安全（黑名单最高优先 → 白名单过滤 → 动作审计 → 行为对齐检测）→ 后置输出审核（拦截+脱敏改写）。
流式 SSE 采用**缓冲模式**：完整响应审核后再下发，安全优先于首字延迟。

### 亮点 4：NHI 动态身份（非人类身份治理）

OAuth 2.0 Client Credentials 签发 15 分钟 JWT + 7 天 refresh + 即时撤销黑名单；
client_secret 与上游 API Key 全部 Fernet 加密落库（零明文存储），明文仅创建/轮转时返回一次；
按身份隔离上游凭据（不同 Agent 各自的 LLM 密钥）；认证爆破锁定 + 分层限流。

### 亮点 5：DevSecOps 自举（用系统保护系统）

系统内置 DevSecOps 扫描平台（bandit/gitleaks/trivy/pip-audit 编排，Celery 异步任务，CI 门禁），
并用 composite action 接入自己的 GitHub Actions——**用 ContentShield 扫描 ContentShield**，
检出即阻断合并。这是"吃自己的狗粮"的安全工程闭环，面试官普遍买账。

### 亮点 6：红队 → 安全对齐数据飞轮（RLHF/后训练视角）

红队结果一键导出为后训练数据：**成功攻击 → DPO 偏好对**（rejected=模型真实屈服回复，
chosen=按攻击类别多模板轮换合成的安全拒绝，防单一句式过拟合；格式兼容 HF trl），
**失败攻击 → SFT 正例**（真实安全回复，兼容训练数据模块回扫）。
这把红队模块从"评估工具"升级为"安全对齐数据工厂"——
对齐层的 helpfulness-harmlessness 权衡、over-refusal 治理，在这里变成了可操作的数据管道。
（进阶路线：用导出数据 DPO 微调小参数 guard 模型，从 guard 消费者变生产者。）

---

## 四、排查故事（面试杀手锏：展示 debugging 方法论）

### 故事 1：三层洋葱式定位 CI 失败 → 发现仓库静默丢代码

**情境**：推送后 GitHub CI 全红，但本地 436 项测试全绿。
**行动**：分层剥洋葱——①失败步骤定位（API 拉 jobs）→ Ruff 格式问题，修；②仍红 → 全新 venv
复现依赖环境，发现 greenlet 缺失（sqlalchemy 未声明 [asyncio] extras），修；③仍红 →
给 pytest 加"失败摘要写入 annotation"的 CI 改进，拿到关键线索 `No module named 'app.models'`；
④Linux/Python3.12 容器完美复现却绿——意识到差异不在环境在**代码版本**，比对提交与工作区。
**结果**：根因是 `.gitignore` 的 `models/` 规则未锚定根目录，把 `backend/app/models/`
（13 个 SQLAlchemy 模型文件）整包忽略——**远程仓库从未有过这个包，任何人 clone 都无法运行**。
改为 `/models/` 锚定 + 补提交，CI 双绿。
**方法论**：复现环境差分（本地✓/CI✗ → 二分环境变量）、让失败自己说话（annotation）、
"本地绿"不等于"提交的代码绿"。

### 故事 2：真实 LLM 验证暴露的隐藏 URL bug

**情境**：AlignmentCheck 单测全绿（fake backend），真实 Ollama 端到端验证时漂移链未拦截。
**行动**：日志定位 → `http://.../v1/v1/chat/completions` 双重 /v1。
**结果**：`_OpenAICompatibleBackend` 固定拼接 `/v1` 前缀，而默认配置 base_url 本身带 `/v1`——
bug 一直存在，因交叉验证从未真实启用而潜伏；`removesuffix("/v1")` 归一化修复，两个功能同时受益。
**方法论**：单测的 fake 会绕过真实集成路径——集成层的验证（哪怕一次真实调用）不可替代。
修复后重测：漂移链被真实拦截（`goal_drift_blocked: 目标转移，从订机票转为导出用户数据`），
正常链放行，黑名单优先级顺序亦验证正确。

---

## 五、量化数据（全部真实可复现）

| 指标 | 数值 | 复现方式 |
|---|---|---|
| 测试 | 436 项全绿（pytest，含 fake-LLM backend 模式） | `cd backend && pytest` |
| CI | 双 workflow 绿（CI + DevSecOps Scan） | GitHub Actions |
| 检测层 | 7 层（L0/L1/L1.5/L2/L3/L4/L5）+ 网关级对齐检测 | 检测台 |
| CodeShield 规则 | 16 条内置危险原语规则 | `detectors/code_shield.py` |
| 决策动作 | block / modify / warn / pass 四级 | `/api/moderate` |
| NHI 凭据 | JWT 15min / refresh 7d / Fernet 加密 | OAuth 端点 |
| 真实拦截演示 | qwen:7b 端到端：漂移链拦截 / 正常链放行 / 黑名单优先 | 网关 curl（见下） |
| 语言/框架 | Python 3.12 / FastAPI / SQLAlchemy 2 / React 18 / Docker Compose | — |

---

## 六、5 分钟演示脚本（面试/展示用，三条 curl 看三道防线）

前置：`bash scripts/start_models_mac.sh --daemon` + `docker compose -f docker-compose.host.yml up -d`，
Settings 页启用 CodeShield(warn) 与 AlignmentCheck(block)，L4 交叉验证指向 Ollama
（base_url=`http://host.docker.internal:11434/v1`，key 随意，model=`qwen:7b`）。

```bash
# ① 危险工具黑名单（第 3 层第一道）：订机票→发邮件 → 黑名单拦截
#    返回 dangerous_action_blocked: 危险工具: send_email 在黑名单中

# ② 行为对齐检测（最外层智能防线）：订机票→upload_file 外传（不在黑名单）
#    返回 goal_drift_blocked: 目标转移，从订机票转为导出用户数据（qwen:7b 真实判定）

# ③ L5 代码安全：检测台输入 eval(os.system(...)) → L5 卡片命中 code:rce（high）
```

（完整 curl 报文见 git log f992b8e 提交说明与 docs；UI 路径：检测台/审计日志-动作审计。）

---

## 七、面试 Q&A 预案

**Q：检测延迟多少？怎么优化的？**
七层并行（asyncio.gather），总延迟=最慢层而非求和；本地正则层微秒级；结果缓存 30s TTL LRU
（重复文本秒回）；CodeShield 纯本地零额外延迟；AlignmentCheck 有轨迹哈希缓存避免重复 LLM 调用。

**Q：LLM 判定挂了怎么办（可用性 vs 安全）？**
fail-open 放行 + 告警日志。理由：对齐检测是增强层不是最后防线，前面有黑名单/白名单/内容检测兜底；
fail-close 会让 LLM 服务抖动放大为全量业务中断。这是显式的权衡（代码注释与 UI 均有说明）。

**Q：误报怎么控制？**
四级决策而非二元拦截；PII 智能降级（modify 替代误拦）；对齐检测 prompt 明确"不确定倾向 aligned"
（宁漏勿误，靠黑名单兜绝对禁止）；新检测层默认 warn 上线观察再切 block（CodeShield/AlignmentCheck
均如此）。

**Q：和商业方案（如 Azure AI Content Safety）比差异？**
模型可插拔（本地 GGUF/云 API/任意 OpenAI 兼容端点，含 Ollama 零成本方案）；Agent 运行时安全
（白名单/对齐检测）是多数商业方案没有的；数据不出本机的 local 模式；开源可审计。

**Q：多实例部署怎么办？**
限流与缓存目前内存态（单实例），多实例需 Redis 化；AlignmentCheck 无状态设计天然免此问题
（这也是它的架构优势之一）。
