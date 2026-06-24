#!/usr/bin/env bash
# =============================================================================
# Apple Silicon 宿主机模型服务启动脚本
#
# 启动两个推理服务（Metal GPU 加速）：
#   1. Llama-Guard-4-12B   → :8082  (llama-server, 危害分类 L2)
#   2. Prompt Guard 2 86M  → :8081  (Python transformers, 注入/越狱 L1)
#
# 用法：
#   bash scripts/start_models_mac.sh             # 前台运行（Ctrl+C 停止）
#   bash scripts/start_models_mac.sh --daemon    # 后台运行
#
# 前置：
#   - brew install llama.cpp
#   - pip install transformers torch fastapi uvicorn
# =============================================================================
set -euo pipefail

MODELS_DIR="$(cd "$(dirname "$0")/.." && pwd)/models"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# 注意：原始 GGUF 的 MoE 元数据有 bug（expert_count=0），需用 _fix_gguf.py 生成 .fixed 版本
GUARD_MODEL="meta-llama.Llama-Guard-4-12B.f16.fixed.gguf"
GUARD_MODEL_FALLBACK="meta-llama.Llama-Guard-4-12B.f16.gguf"
# Prompt Guard 2 86M 是 DeBERTa-v2 分类模型（非 GGUF），用 HF 原始权重目录
PG_MODEL_DIR="Llama-Prompt-Guard-2-86M"

DAEMON=0
[[ "${1:-}" == "--daemon" ]] && DAEMON=1

# ---- 检查工具 ----
if ! command -v llama-server >/dev/null 2>&1; then
  echo "❌ 未找到 llama-server，请先安装：brew install llama.cpp"
  exit 1
fi

# ---- 检查 Llama-Guard-4 模型 ----
GUARD_PATH="$MODELS_DIR/$GUARD_MODEL"
if [[ ! -f "$GUARD_PATH" ]]; then
  GUARD_PATH="$MODELS_DIR/$GUARD_MODEL_FALLBACK"
fi
if [[ ! -f "$GUARD_PATH" ]]; then
  echo "❌ 未找到 Llama-Guard-4 模型: $MODELS_DIR/$GUARD_MODEL"
  echo "   请将 .gguf 文件放入 $MODELS_DIR/"
  echo "   若原始文件元数据有 MoE 断言错误，运行: python3 _fix_gguf.py 生成修复版"
  exit 1
fi
if [[ "$GUARD_PATH" == *"$GUARD_MODEL_FALLBACK" ]]; then
  echo "⚠️  警告：使用未修复的原版 GGUF，可能因 expert_count=0 触发 MoE 断言崩溃"
  echo "   建议运行 python3 _fix_gguf.py 生成 .fixed 版本"
fi

# ---- 检查 Prompt Guard 2（DeBERTa-v2 分类模型）----
PG_DIR="$MODELS_DIR/$PG_MODEL_DIR"
PG_AVAILABLE=0
if [[ -d "$PG_DIR" ]] && [[ -f "$PG_DIR/config.json" ]]; then
  PG_AVAILABLE=1
fi

# ---- Llama-Guard-4 启动参数（:8082）----
echo "🚀 启动 Llama-Guard-4-12B  → http://localhost:8082"
echo "   模型: $GUARD_PATH"
# 注意：Llama-Guard-4 是 MoE 架构，关键参数说明：
#   --fit off     绕过 GGML_ASSERT(n_expert_used <= n_expert) 断言崩溃
#   --no-jinja    绕过 GGUF 内嵌 chat template 的 roles 校验 bug + 输出格式校验 500
#   --cache-ram 0 禁用 prompt cache（cache 复用导致输出不稳定）
#   -np 1         单并行 slot（f16 24GB 大模型并发不稳）
GUARD_ARGS=(
  --model "$GUARD_PATH"
  --host 0.0.0.0 --port 8082
  --alias llama-guard-4-12b
  --gpu-layers 999
  --threads 12
  --ctx-size 8192
  --no-jinja
  --cache-ram 0
  --fit off
  -np 1
)

# ---- 启动逻辑 ----
if [[ $DAEMON -eq 1 ]]; then
  # 后台模式
  nohup llama-server "${GUARD_ARGS[@]}" > /tmp/cs-guard.log 2>&1 &
  echo $! > /tmp/cs-guard.pid
  echo "✅ Llama-Guard-4 后台运行（PID $(cat /tmp/cs-guard.pid)，日志 /tmp/cs-guard.log）"

  if [[ $PG_AVAILABLE -eq 1 ]]; then
    echo "🚀 启动 Prompt Guard 2 86M → http://localhost:8081"
    echo "   模型: $PG_DIR（DeBERTa-v2，Python transformers + MPS）"
    nohup python3 "$PROJECT_DIR/inference/prompt_guard_server.py" \
      --model "$PG_DIR" --port 8081 > /tmp/cs-pg.log 2>&1 &
    echo $! > /tmp/cs-pg.pid
    echo "✅ Prompt Guard 2 后台运行（PID $(cat /tmp/cs-pg.pid)，日志 /tmp/cs-pg.log）"
  else
    echo ""
    echo "⚠️  未找到 Prompt Guard 2: $PG_DIR"
    echo "   Prompt Guard 层会自动 skip。"
    echo "   将 Llama-Prompt-Guard-2-86M 目录放入 $MODELS_DIR/ 后重新运行此脚本。"
  fi

  echo ""
  echo "停止: kill \$(cat /tmp/cs-guard.pid) \$(cat /tmp/cs-pg.pid 2>/dev/null)"
else
  # 前台模式：并行跑，任一退出则全部停止
  trap 'kill 0' EXIT INT TERM
  llama-server "${GUARD_ARGS[@]}" &
  if [[ $PG_AVAILABLE -eq 1 ]]; then
    echo "🚀 启动 Prompt Guard 2 86M → http://localhost:8081"
    python3 "$PROJECT_DIR/inference/prompt_guard_server.py" \
      --model "$PG_DIR" --port 8081 &
  else
    echo "⚠️  Prompt Guard 2 未找到，仅启动 Llama-Guard-4"
  fi
  wait
fi
